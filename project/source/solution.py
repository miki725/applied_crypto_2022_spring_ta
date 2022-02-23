import argparse
import dataclasses
import functools
import getpass
import hashlib
import hmac
import itertools
import json
import pathlib
import secrets
import sys
import typing
import unicodedata

import regex
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq


def log(*args):
    print(*args, file=sys.stdout)


def error(*args):
    print(*args, file=sys.stderr)


def eq(a: bytes, *args: bytes) -> bool:
    """
    constant time comparison but for any number of bytes provided

    >>> eq(b'hello', b'hello', b'hello')
    True
    >>> eq(b'hello', b'hello', b'world')
    False
    """
    compared = sum([int(bytes_eq(a, i)) for i in args])
    return compared == len(args)


def xor(*args: bytes) -> bytes:
    return bytes(functools.reduce(lambda a, b: a ^ b, i) for i in zip(*args))


def hmac_message(data: bytes, key: bytes, method: str = "sha256"):
    return hmac.new(key, data, method).digest()


def aes_ctr_keystream_generator(key: bytes, iv: bytes, length: int = None):
    aes = algorithms.AES(key)
    encryptor = Cipher(algorithm=aes, mode=modes.CTR(iv)).encryptor()
    # since in CTR more, each block is XORed with plaintext, if plaintext is
    # all 0s we effectively can extract the enctyption stream
    dummy = b"\x00" * (length or (aes.key_size // 8))
    while True:
        yield encryptor.update(dummy)


@dataclasses.dataclass
class Keys:
    ITERATIONS = 250_000
    HASH_FUNCTION = "sha256"

    salt: bytes
    master: bytes
    validator: bytes
    feistel: typing.List[bytes]
    mac: bytes
    search_terms: bytes

    @classmethod
    def from_password(cls, password: bytes, salt: bytes = None):
        salt = salt or secrets.token_bytes(16)
        master = hashlib.pbkdf2_hmac(cls.HASH_FUNCTION, password, salt, cls.ITERATIONS)

        aes_key, iv = master[:16], master[16:]
        generator = aes_ctr_keystream_generator(aes_key, iv)

        return cls(
            salt=salt,
            master=master,
            validator=next(generator),
            feistel=[next(generator) for _ in range(4)],
            mac=next(generator),
            search_terms=next(generator),
        )


@dataclasses.dataclass
class WithMAC:
    ciphertext: bytes
    mac: bytes


@dataclasses.dataclass
class Feistel:
    """
    >>> data = bytes(range(32))
    >>> feistel = Feistel(Keys.from_password(b'password'))
    >>> ciphertext = feistel.encrypt(data)
    >>> plaintext = feistel.decrypt(ciphertext)
    >>> assert data == plaintext, (data, plaintext)
    >>> assert ciphertext.ciphertext[:16] != data[:16], ciphertext
    """

    LEFT_BYTES = 16
    keys: Keys

    @classmethod
    def split(cls, data: bytes):
        return data[: cls.LEFT_BYTES], data[cls.LEFT_BYTES :]

    @classmethod
    def ctr_round(cls, data: bytes, key: bytes):
        """
        >>> data = bytes(range(256))
        >>> key = secrets.token_bytes(16)
        >>> ciphertext = Feistel.ctr_round(data, key)
        >>> plaintext = Feistel.ctr_round(ciphertext, key)
        >>> assert data == plaintext, (data, plaintext)
        """
        left, right = cls.split(data)
        keystream = next(aes_ctr_keystream_generator(key, left, len(right)))
        return left + xor(right, keystream)

    @classmethod
    def hmac_round(cls, data: bytes, key: bytes):
        """
        >>> data = bytes(range(256))
        >>> key = secrets.token_bytes(16)
        >>> ciphertext = Feistel.hmac_round(data, key)
        >>> plaintext = Feistel.hmac_round(ciphertext, key)
        >>> assert data == plaintext, (data, plaintext)
        """
        left, right = cls.split(data)
        digest = hmac_message(right, key)
        return xor(left, digest) + right

    def encrypt_or_decrypt(self, data: bytes, decrypt: bool = False):
        assert len(data) >= 32

        round_keys = list(
            zip(
                itertools.cycle(
                    [
                        self.ctr_round,
                        self.hmac_round,
                    ]
                ),
                self.keys.feistel,
            )
        )

        if decrypt:
            round_keys = reversed(round_keys)

        for round, key in round_keys:
            data = round(data, key)

        return data

    def encrypt(self, data: bytes):
        ciphertext = self.encrypt_or_decrypt(data)
        mac = hmac_message(ciphertext, self.keys.mac)
        return WithMAC(ciphertext=ciphertext, mac=mac)

    def decrypt(self, with_mac: WithMAC):
        mac = hmac_message(with_mac.ciphertext, self.keys.mac)
        if not eq(mac, with_mac.mac):
            raise ValueError("invalid mac")
        return self.encrypt_or_decrypt(with_mac.ciphertext, decrypt=True)


@dataclasses.dataclass
class Metadata:
    salt: bytes
    validator: bytes
    mac: bytes
    terms: typing.List[bytes]

    def as_json(self):
        return {
            "salt": self.salt.hex(),
            "validator": self.validator.hex(),
            "mac": self.mac.hex(),
            "terms": [i.hex() for i in self.terms],
        }

    @classmethod
    def from_json(cls, data):
        return cls(
            salt=bytes.fromhex(data["salt"]),
            validator=bytes.fromhex(data["validator"]),
            mac=bytes.fromhex(data["mac"]),
            terms=[bytes.fromhex(i) for i in data["terms"]],
        )


class Text:
    # all characters:
    # https://www.unicode.org/Public/UNIDATA/UnicodeData.txt
    CATEGORIES = [
        # characters
        "Lu",
        "Ll",
        "Lt",
        "Lm",
        "Lo",
        # marks
        "Mn",
        "Mc",
        "Me",
        # numbers
        "Nd",
        "Nl",
        "No",
    ]
    CATEGORIES_RE = regex.compile(
        "[" + "".join([fr"\p{{{i}}}" for i in CATEGORIES]) + "]+"
    )

    @classmethod
    def normalize_word(cls, word: str):
        return unicodedata.normalize("NFC", word.lower())

    @classmethod
    def extract_terms(cls, data: bytes):
        """
        >>> Text.extract_terms("ᾟello cat world\u03681 unimaginatively".encode('utf-8'))
        ['worldͨ1', 'ᾗello', 'worldͨ1*', 'ᾗello*']
        """
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return []

        terms = sorted(
            set(
                cls.normalize_word(i)
                for i in cls.CATEGORIES_RE.findall(text)
                if len(i) >= 4 and len(i) <= 12
            )
        )

        terms = list(
            itertools.chain(
                *[[term[:i] for i in range(4, len(term) + 1)] for term in terms]
            )
        )

        return terms

    @classmethod
    def mac_terms(cls, terms: typing.List[str], key: bytes):
        return [cls.mac_term(i, key) for i in terms]

    @classmethod
    def mac_term(cls, data: str, key: bytes):
        return hmac_message(data.encode("utf-8"), key)


@dataclasses.dataclass
class File:
    path: pathlib.Path
    password: bytes = b""

    _keys: typing.Optional[Keys] = None
    _metadata: typing.Optional[Metadata] = None

    def has_errors(self, to_encrypt: bool = False):
        if not self.path.exists():
            error(f"{self.path}: does not exist")
            return True

        size = self.path.stat().st_size
        if size < 32:
            error(f"{self.path}: {size} is < 32 bytes")
            return True

        if to_encrypt and self.is_already_encrypted():
            error(f"{self.path}: is already encrypted")
            return True

        if not to_encrypt and not self.is_already_encrypted():
            error(f"{self.path}: is not encrypted")
            return True

        return False

    def is_validator_bad(self):
        if self.is_already_encrypted() and not eq(
            self.keys.validator, self.metadata.validator
        ):
            error(f"{self.path}: validator is incorrect")
            return True

        return False

    @property
    def metadata_path(self):
        return self.path.with_name(f".fenc-meta.{self.path.name}")

    @property
    def metadata(self):
        if self._metadata:
            return self._metadata
        data = json.loads(self.metadata_path.read_text())
        self._metadata = Metadata.from_json(data)
        return self._metadata

    @metadata.setter
    def metadata(self, metadata: Metadata):
        self._metadata = metadata

    def is_already_encrypted(self):
        return self.metadata_path.exists()

    @property
    def keys(self):
        if self._keys:
            return self._keys
        self._keys = Keys.from_password(
            password=self.password,
            salt=self.metadata.salt if self.is_already_encrypted() else None,
        )
        return self._keys

    def add_password(self, password: bytes):
        self.password = password
        return self

    def encrypt(self):
        data = self.path.read_bytes()
        encrypted = Feistel(keys=self.keys).encrypt(data)
        self.metadata = Metadata(
            salt=self.keys.salt,
            validator=self.keys.validator,
            mac=encrypted.mac,
            terms=Text.mac_terms(Text.extract_terms(data), self.keys.search_terms),
        )
        self.metadata_path.write_text(json.dumps(self.metadata.as_json(), indent=4))
        self.path.write_bytes(encrypted.ciphertext)

    def decrypt(self):
        data = self.path.read_bytes()
        try:
            decrypted = Feistel(keys=self.keys).decrypt(
                WithMAC(ciphertext=data, mac=self.metadata.mac)
            )
        except ValueError:
            error(f"{self.path}: MAC failed")
        else:
            self.metadata_path.unlink()
            self.path.write_bytes(decrypted)

    def search(self, terms: typing.List[str]):
        mac_terms = Text.mac_terms(terms, self.keys.search_terms)
        if any(i in mac_terms for i in self.metadata.terms):
            error(f"{self.path}")
            return True
        return False


def main(args):
    if args.search:
        password = get_password()

        potential_files = [
            File(path=i).add_password(password) for i in pathlib.Path(".").iterdir()
        ]
        files = [i for i in potential_files if i.is_already_encrypted()]

        if sum(i.is_validator_bad() for i in files) > 0:
            return

        if sum(i.search(args.args) for i in files) == 0:
            error(f"{args.args} were not found in any of the files")

    else:
        files = [File(path=pathlib.Path(i)) for i in args.args]

        if sum(i.has_errors(not args.decrypt) for i in files) > 0:
            return

        password = get_password()
        for i in files:
            i.add_password(password)

        if sum(i.is_validator_bad() for i in files) > 0:
            return

        if args.json:
            log(json.dumps({str(i.path): i.keys.master.hex() for i in files}, indent=4))

        if args.decrypt:
            for i in files:
                i.decrypt()

        else:
            for i in files:
                i.encrypt()


def get_password():
    if sys.stdin.isatty():
        return getpass.getpass("password: ").encode("utf-8")
    else:
        return sys.stdin.readline().strip().encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encrypt/decrypt/search files")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-e",
        dest="encrypt",
        action="store_true",
        help="encrypt provided files",
    )
    group.add_argument(
        "-d",
        dest="decrypt",
        action="store_true",
        help="decrypt provided files",
    )
    group.add_argument(
        "-s",
        dest="search",
        action="store_true",
        help="search files in current folder",
    )
    parser.add_argument(
        "-j",
        dest="json",
        action="store_true",
        help="output debug information to stdout",
    )
    parser.add_argument(
        "args",
        metavar="P",
        type=str,
        nargs="+",
        help="either file paths or search terms",
    )

    args = parser.parse_args()

    main(args)
