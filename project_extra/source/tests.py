from .conftest import Problem, weight


@weight(name="problem 1", worth=1)
def test_problem_1(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 2", worth=1)
def test_problem_2(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 3", worth=1)
def test_problem_3(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 4", worth=1)
def test_problem_4(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 5", worth=1)
def test_problem_5(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 6", worth=1)
def test_problem_6(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 7", worth=1)
def test_problem_7(problem: Problem):
    assert problem.output == problem.reference


@weight(name="problem 8", worth=1)
def test_problem_8(problem: Problem):
    assert set(problem.output) == set(problem.reference)


@weight(name="problem 9", worth=1)
def test_problem_9(problem: Problem):
    assert set(problem.output) == set(problem.reference)


@weight(name="problem 10", worth=1)
def test_problem_10(problem: Problem):
    assert set(problem.output) == set(problem.reference)


@weight(name="problem 11", worth=1)
def test_problem_11(problem: Problem):
    assert set(problem.output) == set(problem.reference)
