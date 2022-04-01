from .conftest import Problem, weight


@weight(name="problem 1", worth=20)
def test_problem_1(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 2", worth=20)
def test_problem_2(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 3", worth=20)
def test_problem_3(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 4", worth=20)
def test_problem_4(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 5", worth=20)
def test_problem_5(problem: Problem):
    assert problem.output == problem.reference
