#!/usr/bin/env python3
import json
import sys

from project.solution import Feistel, Keys, Text, hmac_message


def problem1(data):
    return Keys.from_password(
        bytes.fromhex(data["password"]), bytes.fromhex(data["salt"])
    ).master.hex()


def problem2(data):
    keys = Keys.from_master(bytes.fromhex(data), salt=b"")
    return {
        "validator": keys.validator.hex(),
        "feistel": [i.hex() for i in keys.feistel],
        "mac": keys.mac.hex(),
        "search_terms": keys.search_terms.hex(),
    }


def problem3(data):
    return Feistel.ctr_round(
        bytes.fromhex(data["data"]), bytes.fromhex(data["key"])
    ).hex()


def problem4(data):
    return Feistel.hmac_round(
        bytes.fromhex(data["data"]), bytes.fromhex(data["key"])
    ).hex()


def problem5(data):
    keys = Keys.from_password(b"")
    keys.feistel = [bytes.fromhex(i) for i in data["keys"]]
    return (
        Feistel(keys)
        .encrypt_or_decrypt(bytes.fromhex(data["plaintext"]), decrypt=False)
        .hex()
    )


def problem6(data):
    keys = Keys.from_password(b"")
    keys.feistel = [bytes.fromhex(i) for i in data["keys"]]
    return (
        Feistel(keys)
        .encrypt_or_decrypt(bytes.fromhex(data["ciphertext"]), decrypt=True)
        .hex()
    )


def problem7(data):
    return hmac_message(bytes.fromhex(data["data"]), bytes.fromhex(data["key"])).hex()


def problem8(data):
    return Text.extract_terms(data.encode(), include_star=False)


problem9 = problem8


def problem10(data):
    return Text.normalize_words(Text.extract_terms(data.encode(), include_star=True))


problem11 = problem10


if __name__ == "__main__":
    data = json.loads(sys.stdin.read())
    solutions = {k: globals()[k.replace(" ", "")](v) for k, v in data.items()}
    print(json.dumps(solutions, indent=4))
