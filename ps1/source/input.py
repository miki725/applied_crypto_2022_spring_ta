import json
import secrets


# from https://www.wordexample.com/list/most-common-nouns-english
words = [
    "time",
    "way",
    "year",
    "work",
    "government",
    "day",
    "man",
    "world",
    "life",
    "part",
    "house",
    "course",
    "case",
    "system",
    "place",
    "end",
    "group",
    "company",
    "party",
    "information",
    "school",
    "fact",
    "money",
    "point",
    "example",
    "state",
    "business",
    "night",
    "area",
    "water",
    "thing",
    "family",
    "head",
    "hand",
    "order",
    "john",
    "side",
    "home",
    "development",
    "week",
    "power",
    "country",
    "council",
    "use",
    "service",
    "room",
    "market",
    "problem",
    "court",
    "lot",
    "a",
    "war",
    "police",
    "interest",
    "car",
    "law",
    "road",
    "form",
    "face",
    "education",
    "policy",
    "research",
    "sort",
    "office",
    "body",
    "person",
    "health",
    "mother",
    "question",
    "period",
    "name",
    "book",
    "level",
    "child",
    "control",
    "society",
    "minister",
    "view",
    "door",
    "line",
    "community",
    "south",
    "city",
    "god",
    "father",
    "centre",
    "effect",
    "staff",
    "position",
    "kind",
    "job",
    "woman",
    "action",
    "management",
    "act",
    "process",
    "north",
    "age",
    "evidence",
]

punctuations = ["!", ".", ",", ";", ":"]

whitespaces = ["\t", "\n", "\r"]


def punctuation() -> str:
    return secrets.choice(punctuations)


def whitespace() -> str:
    return secrets.choice(whitespaces)


def word() -> str:
    return secrets.choice(words)


def phrase(n: int) -> str:
    return " ".join([word() for _ in range(n)])


def hexlify(s: str) -> str:
    return s.encode().hex().upper()


def random_hex(min: int, max: int) -> str:
    return secrets.token_hex(secrets.randbelow(max - min) + min)


def random_case(s: str) -> str:
    return "".join(i.upper() if secrets.randbelow(2) else i.lower() for i in s)


if __name__ == "__main__":
    print(
        json.dumps(
            {
                "problem 1": [
                    random_case(random_hex(5, 20)),
                    random_case(random_hex(5, 20)),
                ],
                "problem 2": [
                    hexlify(word()),
                    hexlify(phrase(5) + punctuation()),
                    hexlify(whitespace() + phrase(5) + punctuation()),
                ],
                "problem 3": [
                    hexlify(random_hex(5, 50)),
                    hexlify(random_hex(5, 25)),
                    hexlify(random_hex(5, 15)),
                ],
                "problem 4": [
                    secrets.randbelow(50000) + 1,  #
                    secrets.randbelow(5) + 2,
                ],
            },
            indent=4,
        )
    )
