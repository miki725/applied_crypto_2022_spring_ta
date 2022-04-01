import json
import random
import secrets
import typing

from solution import RSA, is_prime_naive


def between(a: int, b: int):
    return secrets.randbelow(b - a + 1) + a


def random_prime(low: int, high: int):
    while True:
        n = between(low, high)
        if is_prime_naive(n):
            return n


def random_rsa():
    p = q = random_prime(7, 255)
    while p == q:
        q = random_prime(7, 255)
    return RSA(p=p, q=q)


def asdict(data: RSA):
    return {
        "p": data.p,
        "q": data.q,
    }


ALL_PRIMES = [i for i in range(5, 256) if is_prime_naive(i)]


def shuffle(data: typing.List[int]):
    random.shuffle(data)
    return data


if __name__ == "__main__":
    for_encryption = random_rsa()
    for_decryption = random_rsa()
    to_decrypt = for_decryption.encrypt(between(10, for_decryption.l - 1))
    print(
        json.dumps(
            {
                "problem 1": {
                    "nums": sorted(
                        set(
                            shuffle(
                                [between(1, 256) for _ in range(between(5, 10))]
                                + [
                                    secrets.choice(ALL_PRIMES)
                                    for _ in range(between(5, 10))
                                ]
                            )
                        )
                    )
                },
                "problem 2": asdict(random_rsa()),
                "problem 3": asdict(random_rsa()),
                "problem 4": {
                    "x": between(10, for_encryption.l - 1),
                    "e": for_encryption.e,
                    "n": for_encryption.n,
                },
                "problem 5": {
                    "y": to_decrypt,
                    **asdict(for_decryption),
                },
            },
            indent=4,
        )
    )
