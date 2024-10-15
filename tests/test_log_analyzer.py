from contextlib import nullcontext
from typing import Any

import pytest

from src.log_analyzer import calc_is_error_treshold, make_report_data, parse_log_filename


@pytest.mark.parametrize(
    "total,errors,treshold,expected",
    [
        (10, 1, 0.2, False),
        (100, 40, 0.5, False),
        (100, 11, 0.1, True),
        (100, 0, 0, False),
        (10_000, 10_001, None, False),
        (1000, 1001, 123, False),
        (1000, 501, 0.5, True),
    ],
)
def test_calc_is_error_treshold(total: int, errors: int, treshold: float | None, expected: bool) -> None:
    res = calc_is_error_treshold(total, errors, treshold)
    assert res is expected


@pytest.mark.parametrize(
    "filename,expected",
    [
        (
            "syngx-log.log-20241010.gz",
            nullcontext(
                {
                    "name": "syngx-log",
                    "dt": "20241010",
                    "ext": ".gz",
                    "filename": "syngx-log.log-20241010.gz",
                }
            ),
        ),
        (
            "syngx-log.log-20241027",
            nullcontext(
                {
                    "name": "syngx-log",
                    "dt": "20241027",
                    "ext": "",
                    "filename": "syngx-log.log-20241027",
                }
            ),
        ),
        (
            "my-awesome-log",
            nullcontext(
                {
                    "name": "my-awesome-log",
                    "dt": "",
                    "ext": "__broken__",
                }
            ),
        ),
    ],
)
def test_parse_log_filename(filename: str, expected: Any) -> None:
    with expected as e:
        res = parse_log_filename(filename)
        assert res == e


def test_make_report_data() -> None:
    test_data: dict[str, list[dict[str, str]]] = {
        "url1": [
            {"request_time": "0.1"},
            {"request_time": "0.2"},
            {"request_time": "0.3"},
            {"request_time": "0.4"},
            {"request_time": "0.5"},
            {"request_time": "10.1"},
            {"request_time": "0.01"},
        ],
        "url2": [
            {"request_time": "10"},
            {"request_time": "20"},
            {"request_time": "30"},
            {"request_time": "40"},
            {"request_time": "50"},
            {"request_time": "0"},
        ],
        "url3": [],
    }

    res = make_report_data(test_data)
    assert len(res) == 2
    assert sum(r["count_perc"] for r in res) == 100  # type: ignore
    assert sum(r["time_perc"] for r in res) == 100  # type: ignore

    url1 = next(u for u in res if u["url"] == "url1")
    assert url1 == {
        "url": "url1",
        "count": 7,
        "count_perc": 53.84615,
        "time_sum": 11.61,
        "time_perc": 7.184,
        "time_avg": 1.659,
        "time_max": 10.1,
        "time_med": 0.3,
    }

    url2 = next(u for u in res if u["url"] == "url2")
    assert url2 == {
        "url": "url2",
        "count": 6,
        "count_perc": 46.15385,
        "time_sum": 150.0,
        "time_perc": 92.816,
        "time_avg": 25.0,
        "time_max": 50.0,
        "time_med": 25.0,
    }
