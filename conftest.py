import contextlib
import dataclasses
import functools
import itertools
import json
import sys
import typing
import pathlib

import pytest


dir = pathlib.Path(__file__).parent
ARTIFACTS = str(dir / "_artifacts.json")
INPUT = str(dir / "_input.json")
OUTPUT = str(dir / "_output.json")
REFERENCE = str(dir / "_reference.json")


# see https://docs.pytest.org/en/6.2.x/example/simple.html#making-test-result-information-available-in-fixtures
@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item):
    outcome = yield
    outcome = typing.cast(pytest.CollectReport, outcome)
    report = outcome.get_result()
    setattr(item, "report_" + report.when, report)


def did_test_pass(request: pytest.FixtureRequest) -> bool:
    setup_passed = getattr(getattr(request.node, "report_setup", None), "passed", False)
    call_passed = getattr(getattr(request.node, "report_call", None), "passed", False)
    return setup_passed and call_passed


def load_json(path: str, strict: bool = True):
    p = pathlib.Path(path)
    if p.exists():
        data = p.read_text()
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            print(data)
    if strict:
        raise IOError(f"missing {path}")


@pytest.fixture
@functools.lru_cache(1)
def artifacts_data():
    return load_json(ARTIFACTS, strict=False)


@pytest.fixture
@functools.lru_cache(1)
def input_data():
    return load_json(INPUT, strict=True)


@pytest.fixture
@functools.lru_cache(1)
def output_data():
    return load_json(OUTPUT, strict=True)


@pytest.fixture
@functools.lru_cache(1)
def reference_data():
    return load_json(REFERENCE, strict=False)


@dataclasses.dataclass
class Problem:
    artifacts: typing.Any
    input: typing.Any
    output: typing.Any
    reference: typing.Any


@pytest.fixture
def data(artifacts_data, input_data, output_data, reference_data):
    return {
        key: Problem(
            artifacts=artifacts_data.get(key) if artifacts_data else None,
            input=input,
            output=output_data.get(key),
            reference=reference_data.get(key) if reference_data else None,
        )
        for key, input in input_data.items()
    }


@pytest.fixture
def problem(request, data):
    matched = next(
        (
            d
            for k, d in data.items()
            if request.function.__name__.endswith(k.replace(" ", "_"))
            or f"_{k.replace(' ', '_')}_" in request.function.__name__
        ),
        None,
    )
    if not matched:
        raise pytest.UsageError(
            f"Could not match any of {data.keys()} to {request.function.__name__}"
        )
    return matched


@dataclasses.dataclass
class Score:
    name: str
    worth: int
    score: int = 0
    subtests_attempted: int = 0
    subtests_succeeded: int = 0
    subtests_fixture: typing.Any = None

    @contextlib.contextmanager
    def test(self, msg, **kwargs):
        self.subtests_attempted += 1
        with self.subtests_fixture.test(msg, **kwargs) as subtest:
            try:
                yield subtest
            except Exception:
                raise
            else:
                self.subtests_succeeded += 1

    def with_subtests(self, subtests: typing.Any):
        self.subtests_fixture = subtests
        return self

    def finalize(self, passed: bool):
        if self.subtests_attempted:
            self.score = (
                self.worth // self.subtests_attempted
            ) * self.subtests_succeeded
        else:
            self.score = self.worth if passed else 0


ALL_SCORES: typing.Dict[str, Score] = {}


@pytest.fixture(scope="session", autouse=True)
def aggregate_scores():
    yield

    tests = [
        {
            "name": name,
            "max_score": sum([i.worth for i in scores]),
            "score": sum([i.score for i in scores]),
        }
        for name, scores in [
            (name, list(scores))
            for name, scores in itertools.groupby(
                ALL_SCORES.values(), key=lambda i: i.name
            )
        ]
    ]
    report = {
        "stdout_visibility": "visible",
        "tests": tests,
        "output": "Thanks for submitting. Remember that you can re-submit as many times as you like, as long as the assignment is open!",
    }
    json_report = json.dumps(report, indent=4)
    print(json_report, file=sys.stderr)


@pytest.fixture(autouse=True)
def score(
    request: pytest.FixtureRequest,
    subtests: typing.Any,
):
    try:
        score = typing.cast(Score, request.function.score).with_subtests(subtests)
    except AttributeError:
        score = None

    yield score

    if not score:
        return

    score.finalize(passed=did_test_pass(request))


def weight(name: str, worth: int):
    def wrapper(f):
        f.score = ALL_SCORES[f.__name__] = Score(
            name=name,
            worth=worth,
        )
        return f

    return wrapper
