import json
import secrets

from project.solution import Keys
from project.test_utils import GeneratedText, generate_password


if __name__ == "__main__":
    data = [
        # pbkdf
        {
            "password": generate_password().decode(),
            "salt": secrets.token_bytes(16).hex(),
        },
        # master key - generate all keys
        secrets.token_bytes(32).hex(),
        # # ctr round
        {
            "key": secrets.token_bytes(16).hex(),
            "data": secrets.token_bytes(64).hex(),
        },
        # hmac round
        {
            "key": secrets.token_bytes(16).hex(),
            "data": secrets.token_bytes(64).hex(),
        },
        # feistel encrypt
        {
            "keys": [i.hex() for i in Keys.from_password(generate_password()).feistel],
            "plaintext": secrets.token_bytes(64).hex(),
        },
        # feistel decrypt
        {
            "keys": [i.hex() for i in Keys.from_password(generate_password()).feistel],
            "ciphertext": secrets.token_bytes(64).hex(),
        },
        # hmac
        {
            "key": secrets.token_bytes(16).hex(),
            "data": secrets.token_bytes(64).hex(),
        },
        # ascii words
        GeneratedText.generate(10, 10, with_unicode=False).text,
        # unicode words
        GeneratedText.generate(10, 10, with_unicode=True).text,
        # ascii terms
        GeneratedText.generate(10, 10, with_unicode=False).text,
        # unicode terms
        GeneratedText.generate(10, 10, with_unicode=True).text,
    ]
    print(
        json.dumps(
            {f"problem {i + 1}": j for i, j in enumerate(data)},
            indent=4,
        )
    )
