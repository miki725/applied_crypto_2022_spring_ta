import csv
import dataclasses
import functools
import itertools
import pathlib
import secrets
import string
import typing
import unicodedata

from .solution import Text


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


def random_case(word: str):
    return "".join(i.upper() if between(0, 1) else i.lower() for i in word)


@dataclasses.dataclass
class GeneratedText:
    ascii_words: typing.List[str]
    unicode_words: typing.List[str]
    text: str

    def __hash__(self):
        return hash(self.text)

    def random_unicode_word(self):
        return secrets.choice(list(Text.filter_words(self.unicode_words)))

    def random_ascii_word(self):
        return secrets.choice(list(Text.filter_words(self.ascii_words)))

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
    def generate(cls, min_words: int, max_words: int, with_unicode: bool = True):
        unicode_words = (
            [
                cls.generate_word(Text.MIN_CHARS, Text.MAX_CHARS, with_unicode=True)
                for _ in range(between(min_words, max_words))
            ]
            if with_unicode
            else []
        )
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
            if with_unicode and not between(0, 4):
                text += cls.add_punctuation(cls.generate_word(1, 3, with_unicode=True))
                text += cls.generate_whitespace()
            if not between(0, 4):
                text += cls.add_punctuation(cls.generate_word(1, 3, with_unicode=False))
                text += cls.generate_whitespace()
            if with_unicode and not between(0, 4):
                text += cls.add_punctuation(
                    cls.generate_word(13, 20, with_unicode=True)
                )
                text += cls.generate_whitespace()
            if not between(0, 4):
                text += cls.add_punctuation(
                    cls.generate_word(13, 20, with_unicode=False)
                )
                text += cls.generate_whitespace()
        return cls(unicode_words=unicode_words, ascii_words=ascii_words, text=text)
