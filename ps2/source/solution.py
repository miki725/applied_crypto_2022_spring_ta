#!/usr/bin/env python3
"""
https://github.com/viega/applied_crypto_2022_spring/tree/master/ps2
"""
import functools
import itertools
import json
import sys
import typing
from dataclasses import dataclass


def xor(*args) -> bytes:
    return bytes(functools.reduce(lambda a, b: a ^ b, i) for i in zip(*args))


def take_in_chunks(data: bytes, n) -> typing.Iterator[bytes]:
    """
    read data in chunks of n bytes
    inspired by https://more-itertools.readthedocs.io
    """
    idata = iter(data)
    next_chunk = list(itertools.islice(idata, n))
    while len(next_chunk):
        yield bytes(next_chunk)
        next_chunk = list(itertools.islice(idata, n))


T = typing.TypeVar("T")


def log(a: T) -> T:
    print(a, file=sys.stderr)
    return a


@dataclass
class Trade:
    all_bytes: bytes
    """
    all trade bytes
    """

    def __post_init__(self):
        assert len(self.all_bytes) == 16

    @classmethod
    def from_str(cls, data: str) -> typing.List["Trade"]:
        return [cls(i) for i in take_in_chunks(bytes.fromhex(data), 16)]

    @property
    def op(self):
        return self.all_bytes[0:1]

    @property
    def co(self):
        return self.all_bytes[2:6]

    @property
    def shares(self):
        return int(self.all_bytes[8:])

    def does_it_match(self, op: bytes, co: bytes) -> bool:
        return self.op == op and self.co == co

    def does_it_match_any_of(self, other: typing.List["Trade"]) -> bool:
        return any([self.does_it_match(op=i.op, co=i.co) for i in other])

    def swap_op(self):
        self.all_bytes = xor(self.all_bytes, xor(b"B", b"S") + b"\x00" * 15)
        return self

    def swap_shares(self, old: int, new: int):
        template = lambda i: b"\x00" * 8 + "{: <8}".format(i).encode()
        self.all_bytes = xor(self.all_bytes, xor(template(old), template(new)))
        return self


@dataclass
class PlaintextCiphertext:
    ciphertext: Trade
    plaintext: Trade


@dataclass
class Problem1:
    old_pt: str
    old_ct: str
    op_1: str
    co_1: str
    op_2: str
    co_2: str
    new_trades: typing.List[str]

    @property
    def old_trades(self):
        return [
            PlaintextCiphertext(plaintext=p, ciphertext=c)
            for p, c in zip(Trade.from_str(self.old_pt), Trade.from_str(self.old_ct))
        ]

    @property
    def to_replace_with(self) -> typing.Optional[PlaintextCiphertext]:
        return next(
            iter(
                sorted(
                    [
                        i
                        for i in self.old_trades
                        if i.plaintext.op == self.op_2.encode()
                        and i.plaintext.co == self.co_2.encode()
                    ],
                    key=lambda i: i.plaintext.shares,
                    reverse=True,
                )
            ),
            None,
        )

    @property
    def to_match(self) -> typing.List[PlaintextCiphertext]:
        return [
            i
            for i in self.old_trades
            if i.plaintext.does_it_match(op=self.op_1.encode(), co=self.co_1.encode())
        ]

    def replace_trades(self, trades: str) -> str:
        if not self.to_replace_with:
            return trades
        return "".join(
            (
                (
                    self.to_replace_with.ciphertext.all_bytes
                    if trade.does_it_match_any_of([i.ciphertext for i in self.to_match])
                    else trade.all_bytes
                ).hex()
                for trade in Trade.from_str(trades)
            )
        )


def problem1(data: Problem1):
    return [data.replace_trades(i) for i in data.new_trades]


@dataclass
class Problem2:
    old_pt: str
    old_ct: str
    new_ct: str

    @property
    def encryption_stream(self) -> bytes:
        pt = bytes.fromhex(self.old_pt)
        ct = bytes.fromhex(self.old_ct)
        return xor(pt, ct)

    @property
    def decrypted_trades(self) -> str:
        ct = bytes.fromhex(self.new_ct)
        return xor(ct, self.encryption_stream).hex()


def problem2(data: Problem2):
    return data.decrypted_trades


@dataclass
class Problem3:
    todays_ct: str

    @property
    def replaced_trades(self):
        return b"".join(
            [i.swap_op().all_bytes for i in Trade.from_str(self.todays_ct)]
        ).hex()


def problem3(data: Problem3):
    return data.replaced_trades


@dataclass
class Problem4:
    trade_list: typing.List[str]
    expected_num: typing.List[int]
    actual_num: typing.List[int]

    @property
    def replaced_trades(self) -> typing.List[str]:
        return [
            trade.swap_op().swap_shares(old=expected, new=actual).all_bytes.hex()
            for trade, expected, actual in zip(
                Trade.from_str("".join(self.trade_list)),
                self.expected_num,
                self.actual_num,
            )
        ]


def problem4(data: Problem4):
    return data.replaced_trades


if __name__ == "__main__":
    data = json.loads(sys.stdin.read())
    solutions = {
        k: globals()[k.replace(" ", "")](globals()[k.replace(" ", "").title()](**v))
        for k, v in data.items()
    }
    print(json.dumps(solutions, indent=4))
