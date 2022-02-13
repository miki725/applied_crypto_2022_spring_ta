from itertools import zip_longest

from .conftest import Problem, weight, Score


@weight(name="problem 1", worth=30)
def test_problem_1(score: Score, problem: Problem):
    for i, (output, reference) in enumerate(
        zip_longest(problem.output, problem.reference)
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output == reference


@weight(name="problem 2", worth=30)
def test_problem_2(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 3", worth=20)
def test_problem_3(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 4", worth=20)
def test_problem_4(score: Score, problem: Problem):
    for i, (output, reference) in enumerate(
        zip_longest(problem.output, problem.reference)
    ):
        with score.test(msg=f"part {i}", i=i):
            assert output == reference
