import json

if __name__ == "__main__":
    print(
        json.dumps(
            {
                "problem 1": ["fadecafedeadd00d", "AbCdEf01230123AbcDEFFFfOf1"],
                "problem 2": [
                    "68656c6c65",
                    "546869732069732061207465737421",
                    "09546869732069732061207465737421",
                ],
                "problem 3": [
                    "0954686973206973206120746573742111",
                    "7f7f7f7f7f03",
                    "FFFFFFFFFF0000FFFF",
                ],
                "problem 4": [50000, 3],
            },
            indent=4,
        )
    )
