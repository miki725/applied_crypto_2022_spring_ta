#!/usr/bin/env python3
import argparse
import dataclasses
import functools
import getpass
import hashlib
import hmac
import itertools
import json
import pathlib
import re
import secrets
import sys
import typing
import unicodedata

import more_itertools
import regex
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.constant_time import bytes_eq


stdout = sys.stdout
stderr = sys.stderr


def log(*args):
    print(*args, file=stdout)


def error(*args):
    print(*args, file=stderr)


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


def xor(*args: typing.Union[bytes, typing.Iterable[bytes]]) -> bytes:
    """
    >>> xor(b'hello', b'world').hex()
    '1f0a1e000b'
    >>> xor(b'hello', b'world', b'hello') # note it has >2 parameters
    b'world'
    >>> xor(xor(b'hello', b'world'), b'hello') # equivalent to above but longer :D
    b'world'

    >>> xor(b'hello', [b'world']).hex()
    '1f0a1e000b'

    >>> def g(i: bytes):
    ...     while True:
    ...         yield i

    >>> xor(b'hello', g(b'world')).hex()
    '1f0a1e000b'
    >>> xor(b'hellothere', b'worldthere', g(b'hello'))
    b'worldhello'
    """
    return bytes(
        functools.reduce(lambda a, b: a ^ b, i)
        for i in zip(
            *[more_itertools.flatten(more_itertools.collapse(i)) for i in args]
        )
    )


@functools.lru_cache()
def get_password():
    if sys.stdin.isatty():
        return getpass.getpass("password: ").encode("utf-8")
    else:
        return sys.stdin.readline().strip().encode("utf-8")


def hmac_message(data: bytes, key: bytes, method: str = "sha256"):
    return hmac.new(key, data, method).digest()


def aes_ctr_keystream_generator(key: bytes, iv: bytes):
    """
    >>> key = bytes(range(16))
    >>> nonce = b"\\xff" * 16

    # reference
    >>> stream = aes_ctr_keystream_generator(key, nonce)
    >>> (next(stream) + next(stream)).hex()
    '3c441f32ce07822364d7a2990e50bb13c6a13b37878f5b826f4f8162a1c8d879'

    # manual nonce incremeent
    # checks if openssl increments all of 16 bytes of the nonce-counter
    >>> block_one = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(b"\\xff" * 16)).encryptor().update(b"\\x00" * 16)
    >>> block_two = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(b"\\x00" * 16)).encryptor().update(b"\\x00" * 16)
    >>> (block_one + block_two).hex()
    '3c441f32ce07822364d7a2990e50bb13c6a13b37878f5b826f4f8162a1c8d879'
    """
    aes = algorithms.AES(key)
    encryptor = Cipher(algorithm=aes, mode=modes.CTR(iv)).encryptor()
    # since in CTR more, each block is XORed with plaintext, if plaintext is
    # all 0s we effectively can extract the enctyption stream
    dummy = b"\x00" * (aes.key_size // 8)
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
        return cls.from_master(master, salt)

    @classmethod
    def from_master(cls, master: bytes, salt: bytes):
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
        keystream = aes_ctr_keystream_generator(key, left)
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

    def __post_init__(self):
        assert len(self.salt) == 16
        assert len(self.validator) == 16
        assert len(self.mac) == 32
        for term in self.terms:
            assert len(term) == 32

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
        # numbers
        "Nd",
        # connector punctuation
        "Pc",
    ]
    CATEGORY_MATCH = "".join([fr"\p{{{i}}}" for i in CATEGORIES])
    CATEGORIES_RE = regex.compile(f"[{CATEGORY_MATCH}]+")
    ASCII_RE = re.compile(r"[\w\d_]+")

    MIN_CHARS = 4
    MAX_CHARS = 12

    @classmethod
    def normalize_word(cls, word: str):
        return unicodedata.normalize("NFC", word.casefold())

    @classmethod
    def normalize_words(cls, words: typing.Iterable[str]):
        """
        >>> Text.normalize_words(['Hell*', 'Hello', 'Hello*', 'Hellow', 'worl*', 'world*', 'world1'])
        ['hell*', 'hello', 'hello*', 'hellow', 'worl*', 'world*', 'world1']
        >>> Text.normalize_words(['worl*', 'world*', 'worldͨ*', 'worldͨ1', 'ᾟell*', 'ᾟello', 'ᾟello*', 'ᾟellow'])
        ['worl*', 'world*', 'worldͨ*', 'worldͨ1', 'ἧιell*', 'ἧιello', 'ἧιello*', 'ἧιellow']
        """
        return sorted({cls.normalize_word(i) for i in words})

    @classmethod
    def is_word_searchable(
        cls, word: str, min_length: int = MIN_CHARS, max_length: int = MAX_CHARS
    ):
        return min_length <= len(word) <= max_length

    @classmethod
    def filter_words(
        cls,
        words: typing.Iterable[str],
        min_length: int = MIN_CHARS,
        max_length: int = MAX_CHARS,
    ):
        return {i for i in words if cls.is_word_searchable(i, min_length, max_length)}

    @classmethod
    def extract_terms(
        cls, data: bytes, pattern=CATEGORIES_RE, include_star: bool = True
    ):
        """
        >>> Text.extract_terms("Hello cat: world1! - Hellow unimaginatively".encode('utf-8'))
        ['Hell*', 'Hello', 'Hello*', 'Hellow', 'worl*', 'world*', 'world1']
        >>> Text.extract_terms("Hello cat: world1! - Hellow unimaginatively".encode('utf-8'), Text.ASCII_RE)
        ['Hell*', 'Hello', 'Hello*', 'Hellow', 'worl*', 'world*', 'world1']

        >>> Text.extract_terms("ᾟello cat: world\u03681! - ᾟellow unimaginatively".encode('utf-8'))
        ['worl*', 'world*', 'worldͨ*', 'worldͨ1', 'ᾟell*', 'ᾟello', 'ᾟello*', 'ᾟellow']
        >>> Text.extract_terms("ᾟello cat: world\u03681! - ᾟellow unimaginatively".encode('utf-8'), Text.ASCII_RE)
        ['worl*', 'world', 'ᾟell*', 'ᾟello', 'ᾟello*', 'ᾟellow']
        """
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return []

        terms = cls.filter_words(pattern.findall(text))

        if include_star:
            for term in list(terms):
                terms |= {f"{term[:i]}*" for i in range(4, len(term))}

        return sorted(terms)

    @classmethod
    def mac_terms(cls, terms: typing.Iterable[str], key: bytes):
        return sorted([cls.mac_term(i, key) for i in terms])

    @classmethod
    def mac_term(cls, data: str, key: bytes):
        return hmac_message(data.encode("utf-8"), key)


@dataclasses.dataclass
class File:
    METADATA_PREFIX = ".fenc-meta."

    path: pathlib.Path

    _password: typing.Optional[bytes] = None
    _keys: typing.Optional[Keys] = None
    _metadata: typing.Optional[Metadata] = None

    def has_errors(self, to_encrypt: bool = False):
        if not self.path.exists():
            error(f"{self.path}: does not exist")
            return True

        size = self.path.stat().st_size
        if size < 32:
            error(f"{self.path}: too small - {size} is < 32 bytes")
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
            error(f"{self.path}: password does not match")
            return True

        return False

    @property
    def metadata_path(self):
        return self.path.with_name(f"{self.METADATA_PREFIX}{self.path.name}")

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

    @property
    def password(self):
        return self._password or get_password()

    def encrypt(self):
        data = self.path.read_bytes()
        encrypted = Feistel(keys=self.keys).encrypt(data)
        terms = Text.extract_terms(data)
        normalized_terms = Text.normalize_words(terms)
        self.metadata = Metadata(
            salt=self.keys.salt,
            validator=self.keys.validator,
            mac=encrypted.mac,
            terms=Text.mac_terms(normalized_terms, self.keys.search_terms),
        )
        self.path.write_bytes(encrypted.ciphertext)
        self.metadata_path.write_text(json.dumps(self.metadata.as_json(), indent=4))

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
        normalized_terms = Text.normalize_words(terms)
        mac_terms = Text.mac_terms(normalized_terms, self.keys.search_terms)
        if any(i in mac_terms for i in self.metadata.terms):
            log(f"{self.path}")
            return True
        return False

    @property
    def debug_json(self):
        return {str(self.path): self.keys.master.hex()}


def log_json(files: typing.List[File]):
    log(
        json.dumps(
            functools.reduce(lambda a, b: {**a, **b}, (i.debug_json for i in files)),
            indent=4,
        )
    )


def main(args):
    if args.search:
        potential_files = [File(path=i) for i in pathlib.Path(".").iterdir()]
        encrypted_files = [i for i in potential_files if i.is_already_encrypted()]

        if not encrypted_files:
            error("no encrypted files found")
            return 1

        files = [i for i in encrypted_files if not i.is_validator_bad()]

        if not files:
            error("no files to search with matching password")
            return 1

        if not get_password():
            error("no password provided")
            return 1

        if args.json:
            log_json(files)

        if sum(i.search(args.args) for i in files) == 0:
            error(f"{args.args} were not found in any of the files")

    else:
        files = [File(path=pathlib.Path(i)) for i in args.args]

        # validation pass without requiring password
        if sum(i.has_errors(not args.decrypt) for i in files) > 0:
            return 1

        if not get_password():
            error("no password provided")
            return 1

        # validation pass whicn requires password
        # separate pass allows to fail early without prompting above without password prompt
        if sum(i.is_validator_bad() for i in files) > 0:
            return 1

        if args.json:
            log_json(files)

        if args.decrypt:
            for i in files:
                i.decrypt()

        else:
            for i in files:
                i.encrypt()

    return 0


if __name__ == "__main__":
    # force everything to go to stdout by default
    sys.stdout = sys.stderr

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

    sys.exit(main(args))
