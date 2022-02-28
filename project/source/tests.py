import csv
import dataclasses
import functools
import itertools
import json
import os
import pathlib
import secrets
import string
import typing
import unicodedata

import pytest

from .conftest import Shell, shell, weight
from .solution import Feistel, File as FileEncryptor, Keys, Metadata, Text


@pytest.fixture(autouse=True)
def tmp(tempdir):
    yield tempdir


PS = pathlib.Path(
    os.environ.get("PS", str(pathlib.Path(__file__).parent / "solution.py"))
)


ALPHABET = string.ascii_letters + string.digits
UNICODE_ALPHABET = ""
PUNCTUATION = string.punctuation
WHITESPACE = string.whitespace


UNICODE_PATH = pathlib.Path(__file__).parent / "unicode_data.csv"


def name_to_chr(name: str):
    try:
        return unicodedata.lookup(name)
    except KeyError:
        return ""


# more at https://www.unicode.org/L2/L1999/UnicodeData.html
with UNICODE_PATH.open("r") as fid:
    reader = csv.DictReader(
        fid,
        delimiter=";",
        fieldnames=[
            "code",
            "name",
            "category",
            "classes",
            "bidirectional",
            "decomposition",
            "decimal",
            "digit",
            "numeric",
            "mirrored",
            "unicode_name",
            "comment",
            "uppercase",
            "lowercase",
            "titlecase",
        ],
    )
    key = lambda i: i["category"]
    for category, characters in itertools.groupby(sorted(reader, key=key), key=key):
        if category in Text.CATEGORIES:
            chars = [
                name_to_chr(i["name"]) for i in characters if name_to_chr(i["name"])
            ]
            UNICODE_ALPHABET += "".join(
                secrets.choice(chars) for _ in range(min(len(chars), 10))
            )


cache = typing.cast(typing.Callable, lambda f: functools.lru_cache()(f))


def between(a: int, b: int):
    return secrets.randbelow(b - a + 1) + a


def generate_password(length: int = 16):
    return secrets.token_bytes(length).hex().encode("utf-8")


def generate_filename(length: int = 16):
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


@dataclasses.dataclass
class GeneratedText:
    ascii_words: typing.List[str]
    unicode_words: typing.List[str]
    text: str

    def __hash__(self):
        return hash(self.text)

    def random_unicode_word(self):
        return secrets.choice(Text.filter_words(self.unicode_words))

    def random_ascii_word(self):
        return secrets.choice(Text.filter_words(self.ascii_words))

    @property
    @cache
    def matched_unicode_terms(self):
        return Text.extract_terms(self.text.encode("utf-8"))

    @property
    @cache
    def matched_ascii_terms(self):
        return Text.extract_terms(self.text.encode("utf-8"), pattern=Text.ASCII_RE)

    @property
    @cache
    def matched_no_star_terms(self):
        return Text.extract_terms(
            self.text.encode("utf-8"), pattern=Text.ASCII_RE, include_star=False
        )

    @classmethod
    def generate_word(cls, min_chars: int, max_chars: int, with_unicode: bool = True):
        word = "".join(
            secrets.choice(
                UNICODE_ALPHABET + ALPHABET * 5 if with_unicode else ALPHABET
            )
            for _ in range(between(min_chars, max_chars))
        )
        return word

    @classmethod
    def add_punctuation(cls, word: str):
        prefix = "".join(secrets.choice(PUNCTUATION) for _ in range(between(0, 1)))
        suffix = "".join(secrets.choice(PUNCTUATION) for _ in range(between(0, 1)))
        return prefix + word + suffix

    @classmethod
    def generate_punctuation_word(cls):
        return "".join(secrets.choice(PUNCTUATION) for _ in range(between(4, 8)))

    @classmethod
    def generate_whitespace(cls):
        return "".join(secrets.choice(WHITESPACE) for _ in range(between(1, 4)))

    @classmethod
    def generate(cls, min_words: int, max_words: int):
        unicode_words = [
            cls.generate_word(Text.MIN_CHARS, Text.MAX_CHARS, with_unicode=True)
            for _ in range(between(min_words, max_words))
        ]
        ascii_words = [
            cls.generate_word(Text.MIN_CHARS, Text.MAX_CHARS, with_unicode=False)
            for _ in range(between(min_words, max_words))
        ]
        text = ""
        for word in ascii_words + unicode_words:
            text += cls.add_punctuation(word)
            text += cls.generate_whitespace()
            if not between(0, 50):
                text += cls.generate_punctuation_word()
                text += cls.generate_whitespace()
            # add shorter and longer unsearcheable words
            if not between(0, 2):
                text += cls.add_punctuation(cls.generate_word(1, 3, with_unicode=True))
                text += cls.generate_whitespace()
                text += cls.add_punctuation(cls.generate_word(1, 3, with_unicode=False))
                text += cls.generate_whitespace()
        return cls(unicode_words=unicode_words, ascii_words=ascii_words, text=text)


@dataclasses.dataclass
class File:
    path: pathlib.Path = dataclasses.field(init=False)

    stdout: bytes = dataclasses.field(init=False, repr=False, default=b"")
    password: typing.Optional[bytes] = dataclasses.field(
        init=False, repr=False, default=b""
    )
    written_text: GeneratedText = dataclasses.field(init=False, repr=False)

    def __hash__(self):
        return hash(str(self.path))

    def __eq__(self, other: "File"):
        return self.path.name == other.path.name

    def __post_init__(self):
        self.path = pathlib.Path(generate_filename())

    @classmethod
    def from_path(cls, path: pathlib.Path):
        file = cls()
        file.path = path
        return file

    def with_result(self, password: typing.Optional[bytes], stdout: bytes):
        self.password = self.password or password
        self.stdout = stdout
        return self

    @property
    def metadata_path(self):
        return self.path.parent / f"{FileEncryptor.METADATA_PREFIX}{self.path.name}"

    @property
    @cache
    def metadata(self):
        data = json.loads(self.metadata_path.read_bytes())
        assert set(data.keys()) == {
            "salt",
            "validator",
            "mac",
            "terms",
        }, "metadata file has extra keys"
        return Metadata.from_json(data)

    @property
    @cache
    def master_key(self):
        return bytes.fromhex(json.loads(self.stdout)[str(self.path)])

    @property
    @cache
    def keys(self):
        return Keys.from_master(self.master_key, self.metadata.salt)

    @property
    @cache
    def derived_keys(self):
        return Keys.from_password(self.password or b"", self.metadata.salt)

    @property
    def size(self):
        return self.path.stat().st_size

    @property
    def data(self):
        return self.path.read_bytes()

    def write(self, data: bytes):
        self.written_data = data
        self.path.write_bytes(data)
        self.written_size = len(data)
        return self

    def write_binary(self, min_bytes: int, max_bytes: int):
        return self.write(secrets.token_bytes(between(min_bytes, max_bytes)))

    def write_words(self, min_words: int, max_words: int):
        self.written_text = GeneratedText.generate(min_words, max_words)
        return self.write(self.written_text.text.encode("utf-8"))

    def encrypt(self, password: bytes = None):
        file = FileEncryptor(self.path, _password=password)
        file.encrypt()
        self.password = password
        self.stdout = json.dumps(file.debug_json).encode()
        return self

    def verify_encryption(self):
        encrypted = Feistel(self.keys).encrypt(self.written_data)
        assert self.size == self.written_size
        assert self.data != self.written_data
        assert self.data == encrypted.ciphertext
        assert self.metadata_path.exists()
        assert self.metadata.mac == encrypted.mac
        return True

    def verify_decryption(self):
        assert self.size == self.written_size
        assert self.data == self.written_data
        assert not self.metadata_path.exists()
        return True

    def verify_keys(self):
        assert self.metadata.validator == self.keys.validator
        return True


@dataclasses.dataclass
class Program(Shell):
    files: typing.List[File] = dataclasses.field(default_factory=list)
    terms: typing.List[str] = dataclasses.field(default_factory=list)
    found_files: typing.Set[File] = dataclasses.field(default_factory=set)

    @classmethod
    def call(cls, args: str, password: bytes = None):
        return shell(
            cmd=f"{PS} {args}",
            stdin=password,
        )

    @classmethod
    def encrypt(cls, files: typing.List[File], password: bytes = None):
        result = cls.call(
            f"-j -e {' '.join(str(i.path) for i in files)}", password=password
        )
        return cls(
            files=[
                i.with_result(password=password, stdout=result.stdout) for i in files
            ],
            **dataclasses.asdict(result),
        )

    @classmethod
    def decrypt(cls, files: typing.List[File], password: bytes = None):
        result = cls.call(
            f"-j -d {' '.join(str(i.path) for i in files)}", password=password
        )
        return cls(
            files=[
                i.with_result(password=password, stdout=result.stdout) for i in files
            ],
            **dataclasses.asdict(result),
        )

    @classmethod
    def search(cls, terms: typing.List[str], password: bytes = None):
        result = cls.call(f"-s {' '.join(terms)}", password=password)
        found = [
            File.from_path(pathlib.Path(i.strip()))
            for i in result.stdout.decode("utf-8").splitlines()
            if i.strip()
        ]
        program = cls(
            files=[],
            terms=terms,
            **dataclasses.asdict(result),
        )
        program.found_files = set(found)
        return program

    @property
    def files_in_folder(self):
        return len(list(self.file.path.parent.iterdir()))

    @property
    def file(self):
        return self.files[0]


@weight(name="general", worth=1)
def test_no_multiple_flags():
    """
    ensure that program does not accept multiple program flags at once
    """
    file = File().write(secrets.token_bytes(32))
    assert not Program.call(f"-e -d -s {file.path}")
    assert not Program.call(f"-e -d {file.path}")
    assert not Program.call(f"-d -s {file.path}")
    assert not Program.call(f"-e -s {file.path}")


@pytest.mark.xfail
@weight(name="encrypt", worth=1)
def test_encrypt_no_password():
    """
    encrypt should exit >0 when no password is given
    """
    file = File().write(secrets.token_bytes(32))
    program = Program.encrypt([file])
    assert not program, "must require password"


@pytest.mark.xfail
@weight(name="encrypt", worth=1)
def test_encrypt_missing_file():
    """
    encrypt should exit >0 when file to be encrypted does not exist
    """
    file = File()
    program = Program.encrypt([file], generate_password())
    assert not program, "should not encrypt non-existing file"


@weight(name="encrypt", worth=1)
def test_encrypt_small():
    """
    encrypt should not encrypt small <32byte files
    """
    file = File().write(secrets.token_bytes(31))
    program = Program.encrypt([file])
    assert not program, "should not encrypt small files"


@weight(name="encrypt", worth=1)
def test_encrypt_no_debug():
    """
    encrypt should not print anything to stdout without -j flag
    """
    file = File().write(secrets.token_bytes(32))
    result = Program.call(f"-e {file.path}")
    assert not result.stdout, "nothing should go to stdout"


@weight(name="encrypt", worth=1)
def test_encrypt_already_encrypted():
    """
    encrypt should not encrypt already encrypted files
    """
    password = generate_password()
    file = File().write(secrets.token_bytes(32)).encrypt(password)
    program = Program.encrypt([file], password)
    assert not program, "should not encrypt already encrypted file"


@weight(name="encrypt", worth=1)
def test_encrypt_binary():
    """
    encrypt should be able to encrypt binary files
    this also checks how file was encrypted
    """
    file = File().write_binary(2 ** 9, 2 ** 11)
    program = Program.encrypt([file], generate_password())
    assert program
    assert program.files_in_folder == 2
    assert file.metadata.terms == []
    assert file.verify_keys()
    assert file.verify_encryption()


@weight(name="encrypt", worth=1)
def test_encrypt_multiple_files():
    """
    encrypt should be able to encrypt multiple files at once
    each encrypted file is checked of how it was encrypted
    """
    files = [
        File().write_binary(2 ** 9, 2 ** 11),
        File().write_binary(2 ** 9, 2 ** 11),
    ]
    program = Program.encrypt(files, generate_password())
    assert program
    assert program.files_in_folder == 4
    for file in files:
        assert file.verify_keys()
        assert file.verify_encryption()


@weight(name="encrypt", worth=1)
def test_encrypt_text():
    """
    encrypt should be able to encrypt text files
    this also checks how file was encrypted
    """
    file = File().write_words(10, 50)
    program = Program.encrypt([file], generate_password())
    assert program
    assert program.files_in_folder == 2
    assert file.metadata_path.exists()
    assert len(file.metadata.terms) > 0
    assert file.verify_keys()
    assert file.verify_encryption()


@weight(name="encrypt", worth=1)
def test_encrypt_text_no_star_terms():
    """
    encrypt should find ascii search terms to go in metadata file
    this test checks that at least all the ascii words were found without * search terms
    """
    file = File().write_words(10, 50)
    program = Program.encrypt([file], generate_password())
    assert program
    assert len(file.metadata.terms) >= len(file.written_text.ascii_words)


@weight(name="encrypt", worth=1)
def test_encrypt_text_star_terms():
    """
    encrypt should find ascii search terms to go in metadata file
    this test checks that at least all the ascii words were found with some * search terms
    """
    file = File().write_words(10, 50)
    program = Program.encrypt([file], generate_password())
    assert program
    assert len(file.metadata.terms) >= min(
        len(file.written_text.matched_ascii_terms),
        len(file.written_text.matched_unicode_terms),
    )


@pytest.mark.xfail
@weight(name="encrypt", worth=1)
def test_encrypt_text_all_unicode_categories():
    """
    encrypt should find all unicode group search terms to go in metadata file along with * search terms
    """
    file = File().write_words(10, 50)
    program = Program.encrypt([file], generate_password())
    assert program
    assert len(file.metadata.terms) == len(file.written_text.matched_unicode_terms)


@weight(name="integration", worth=1)
def test_encrypt_then_decrypt():
    """
    decrypt should be able to decrypt encrypted file
    """
    file = File().write_binary(2 ** 9, 2 ** 11)
    encrypted = Program.encrypt([file], generate_password())
    assert encrypted
    assert file.verify_encryption()
    decrypted = Program.decrypt([file], file.password)
    assert decrypted
    assert file.verify_decryption()


@weight(name="integration", worth=1)
def test_encrypt_then_search_then_decrypt():
    """
    encrypt, then search, then decrypt all should be able to run on the same file in sequence
    """
    file = File().write_words(15, 30)
    encrypted = Program.encrypt([file], generate_password())
    assert encrypted
    assert file.verify_encryption()
    search = Program.search(
        [
            file.written_text.random_unicode_word(),
        ],
        file.password,
    )
    assert search
    decrypted = Program.decrypt([file], file.password)
    assert decrypted
    assert file.verify_decryption()


@weight(name="decrypt", worth=1)
def test_decrypt_no_debug():
    """
    decrypt should not output anything to stdout without -j flag
    """
    file = File().write(secrets.token_bytes(32)).encrypt(generate_password())
    result = Program.call(f"-d {file.path}")
    assert not result.stdout, "nothing should go to stdout"


@pytest.mark.xfail
@weight(name="decrypt", worth=1)
def test_decrypt_no_password():
    """
    decrypt program should exit >0 without given password
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    program = Program.decrypt([file])
    assert not program


@weight(name="decrypt", worth=1)
def test_decrypt_diff_password():
    """
    decrypt should exit >0 if decryption password does not match encryption passoword
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    program = Program.decrypt([file], generate_password())
    assert not program


@pytest.mark.xfail
@weight(name="decrypt", worth=1)
def test_decrypt_no_file():
    """
    decrypt should exit >0 when attempting to decrypt non-existing file
    """
    file = File()
    program = Program.decrypt([file], generate_password())
    assert not program


@weight(name="decrypt", worth=1)
def test_decrypt_not_encrypted():
    """
    decrypt should exit >0 when decrypting non-encrypted file
    """
    file = File().write_binary(2 ** 9, 2 ** 11)
    program = Program.decrypt([file], generate_password())
    assert not program


@weight(name="decrypt", worth=1)
def test_decrypt():
    """
    decrypt should be able to decrypt binary file
    decrypted file is checked that it matches initial plaintext file
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    program = Program.decrypt([file], file.password)
    assert program
    assert program.files_in_folder == 1
    assert file.verify_decryption()


@weight(name="decrypt", worth=1)
def test_decrypt_mismatching_mac():
    """
    decrypt should not attempt to decrypt files where MAC does not match
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    changed_data = file.written_data[:-2] + b"\x00" * 2
    file.path.write_bytes(changed_data)
    program = Program.decrypt([file], file.password)
    assert program
    assert program.files_in_folder == 2
    assert file.verify_keys()
    assert file.path.read_bytes() == changed_data


@weight(name="decrypt", worth=1)
def test_decrypt_multiple_files():
    """
    decrypt should be able to decrypt multiple files
    each decrypted file is checked that it matches initial plaintext file
    """
    password = generate_password()
    files = [
        File().write_binary(2 ** 9, 2 ** 11).encrypt(password),
        File().write_binary(2 ** 9, 2 ** 11).encrypt(password),
    ]
    program = Program.decrypt(files, password)
    assert program
    assert program.files_in_folder == 2
    for file in files:
        assert file.verify_decryption()


@weight(name="decrypt", worth=1)
def test_decrypt_multiple_files_mismatching_passwords():
    """
    decrypt should exit >0 if any of the files to be decrypted do not match password
    """
    password = generate_password()
    files = [
        File().write_binary(2 ** 9, 2 ** 11).encrypt(password),
        File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password()),
    ]
    program = Program.decrypt(files, password)
    assert not program


@weight(name="decrypt", worth=1)
def test_decrypt_missing_metadata():
    """
    decrypt should exit >0 when metadata file is missing
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    file.metadata_path.unlink()
    program = Program.decrypt([file], file.password)
    assert not program


@weight(name="decrypt", worth=1)
def test_decrypt_missing_file():
    """
    decrypt should exit >0 when file is missing but metadata file is present
    """
    file = File().write_binary(2 ** 9, 2 ** 11).encrypt(generate_password())
    file.path.unlink()
    program = Program.decrypt([file], file.password)
    assert not program


@pytest.mark.xfail
@weight(name="search", worth=1)
def test_search_no_files():
    """
    search should exit >0 when no files are present
    """
    program = Program.search(["foo"], generate_password())
    assert not program


@pytest.mark.xfail
@weight(name="search", worth=1)
def test_search_no_password():
    """
    search should exit >0 when no password was provided
    """
    File().write_words(10, 50).encrypt(generate_password())
    program = Program.search(["foo"])
    assert not program


@pytest.mark.xfail
@weight(name="search", worth=1)
def test_search_no_files_with_same_password():
    """
    search should exit >0 when no files with matching password were found
    """
    File().write_words(50, 100).encrypt(generate_password())
    program = Program.search(["foo"], generate_password())
    assert not program


@weight(name="search", worth=1)
def test_search_different_term():
    """
    search should not any files with search term not present in files
    """
    file = File().write_words(50, 100).encrypt(generate_password())
    program = Program.search(["hello"], file.password)
    assert program
    assert program.found_files == set()


@weight(name="search", worth=1)
def test_search():
    """
    search should be able to find file by full word present in file
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_ascii_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@weight(name="search", worth=1)
def test_search_mismatching_validator():
    """
    search should validate validator before searching file
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    File().write_words(5, 10).encrypt(file.password)
    file.metadata.validator = file.metadata.validator[:-2] + b"\x00" * 2
    file.metadata_path.write_text(json.dumps(file.metadata.as_json()))
    program = Program.search(
        [
            file.written_text.random_ascii_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == set()


@weight(name="search", worth=1)
def test_search_empty_file():
    """
    search should only use metadata file after plaintext is encrypted
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    file.path.write_bytes(b"")
    program = Program.search(
        [
            file.written_text.random_ascii_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@weight(name="search", worth=1)
def test_search_multiple_terms():
    """
    search should be able to find file when searching by multiple full words from file
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_ascii_word(),
            file.written_text.random_ascii_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@weight(name="search", worth=1)
def test_search_multiple_passwords():
    """
    search should be able to find files with search terms even if other files dont match passwords
    """
    File().write_words(5, 10).encrypt(generate_password())
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_ascii_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@weight(name="search", worth=1)
def test_search_multiple_files():
    """
    search shoulg be able to find multiple files with terms from different files
    """
    file1 = File().write_words(5, 10).encrypt(generate_password())
    file2 = File().write_words(5, 10).encrypt(file1.password)
    File().write_words(5, 10).encrypt(file1.password)
    File().write_binary(32, 64).encrypt(file1.password)
    File().write_words(5, 10).encrypt(file1.password)
    program = Program.search(
        [
            file1.written_text.random_ascii_word(),
            file2.written_text.random_ascii_word(),
        ],
        file1.password,
    )
    assert program
    assert program.found_files == {file1, file2}


@pytest.mark.xfail
@weight(name="search", worth=1)
def test_search_unicode():
    """
    search should be able to find files by using full unicode search terms
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_unicode_word(),
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@weight(name="search", worth=1)
def test_search_star():
    """
    search should be able find file with partial search term

    for example if file contains "building", "build*" should be able to find the file
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_ascii_word()[:-1] + "*",
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}


@pytest.mark.xfail
@weight(name="search", worth=1)
def test_search_unicode_star():
    """
    search should be able find file with partial search unicode term

    for example if file contains "вітаємо" (hello in Ukranian), "вітаєм*" should be able to find the file
    """
    file = File().write_words(5, 10).encrypt(generate_password())
    program = Program.search(
        [
            file.written_text.random_unicode_word()[:-1] + "*",
        ],
        file.password,
    )
    assert program
    assert program.found_files == {file}
