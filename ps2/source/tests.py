import typing
from itertools import islice, zip_longest

from .conftest import Problem, Score, weight


def take_in_chunks(data: str, n) -> typing.Iterator[str]:
    """
    read data in chunks of n bytes
    inspired by https://more-itertools.readthedocs.io
    """
    idata = iter(data)
    next_chunk = list(islice(idata, n))
    while len(next_chunk):
        yield "".join(next_chunk)
        next_chunk = list(islice(idata, n))


@weight(name="problem 1", worth=30)
def test_problem_1(score: Score, problem: Problem):
    for i, (input, output, reference) in enumerate(
        zip_longest(problem.input["new_trades"], problem.output, problem.reference)
    ):
        # replaced target trades with one of possible trades
        # but does not guarantee its replaced with best trade
        with score.test(msg=f"part {i} (one of possible trades)", i=i, weight=7):
            valid_mappings = {
                target.lower(): list(problem.artifacts["possible"].values())
                for target in problem.artifacts["targets"].values()
            }
            for input_trade, output_trade in zip_longest(
                take_in_chunks(input, 32), take_in_chunks(output, 32)
            ):
                if input_trade.lower() in problem.artifacts["targets"].values():
                    assert output_trade.lower() in valid_mappings[input_trade.lower()]
                else:
                    assert output_trade.lower() == input_trade.lower()

        # replaced with best possible trade
        with score.test(msg=f"part {i} (best trade)", i=i, weight=8):
            assert output.lower() == reference.lower()


@weight(name="problem 2", worth=30)
def test_problem_2(problem: Problem):
    assert problem.output.lower() == problem.artifacts["expected"].lower()


@weight(name="problem 3", worth=20)
def test_problem_3(problem: Problem):
    assert problem.output.lower() == problem.artifacts["expected"].lower()


@weight(name="problem 4", worth=20)
def test_problem_4(score: Score, problem: Problem):
    for i, (output, artifacts) in enumerate(
        zip_longest(problem.output, problem.artifacts["expected"])
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output.lower() == artifacts.lower()
