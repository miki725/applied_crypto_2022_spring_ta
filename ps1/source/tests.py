from itertools import zip_longest

from .conftest import Problem, Score, weight


@weight(name="problem 1", worth=2)
def test_problem_1(score: Score, problem: Problem):
    for i, (output, reference) in enumerate(
        zip_longest(problem.output, problem.reference)
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output == reference


@weight(name="problem 2", worth=3)
def test_problem_2(score: Score, problem: Problem):
    for i, (output, reference) in enumerate(
        zip_longest(problem.output, problem.reference)
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output == reference


@weight(name="problem 3", worth=3)
def test_problem_3(score: Score, problem: Problem):
    for i, (output, reference) in enumerate(
        zip_longest(problem.output, problem.reference)
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output.lower() == reference.lower()


@weight(name="problem 4", worth=2, manual=True)
def test_problem_4(score: Score, problem: Problem):
    for i, (output, input) in enumerate(zip_longest(problem.output, problem.input)):
        with score.test(msg=f"part {i}", i=i):
            assert output >= 0
            assert output < input
