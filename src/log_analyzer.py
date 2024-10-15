# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

import argparse
import gzip
import json
import logging
import os
import re
import statistics
from collections import ChainMap
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from string import Template
from typing import Any, Generator, Mapping, MutableMapping

import structlog


def log_level_filter(
    _: Any,  # pylint: disable=unused-argument
    __: Any,  # pylint: disable=unused-argument, invalid-name
    event_dict: MutableMapping[str, Any],
) -> MutableMapping[str, Any]:
    if event_dict.get("level") not in ["debug", "info", "error"]:
        raise structlog.DropEvent
    return event_dict


structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
    processors=[
        structlog.processors.add_log_level,
        log_level_filter,
        structlog.processors.StackInfoRenderer(),
        # structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso", utc=False),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
)
log = structlog.getLogger()

config = {"REPORT_SIZE": 1000, "REPORT_DIR": "./reports", "LOG_DIR": "./log"}


logline_format = re.compile(
    r"""(?P<remote_addr>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<remote_user>\S+)  (?P<http_x_real_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|-) \[(?P<time_local>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<request>.+)(http\/1\.1\")) (?P<status>\d{3}) (?P<body_bytes_sent>\d+) ([\"](?P<http_refferer>(\-)|(.+))[\"]) (\"(?P<http_user_agent>.+)\") \"-\" \"(?P<http_X_REQUEST_ID>\d{5,15}-\d{5,15}-\d{1,4}-\d{5,15})\" \"(?P<http_X_RB_USER>.*)\" (?P<request_time>\d.\d{0,10})""",  # pylint:disable=line-too-long  # noqa: E501
    re.IGNORECASE,
)
logname_format = re.compile(r"""(?P<name>\S+).log-(?P<dt>\d{8})(?P<ext>(.\S+)?)""", re.IGNORECASE)

allowed_ext = ["", ".gz"]


@dataclass(frozen=True)
class LogFileMeta:
    path: Path
    filename: str
    dt: date
    ext: str


def log_reader(opener: Any, mode: str, path: Path) -> Generator[str, None, None]:
    # pylint: disable=use-yield-from
    try:
        with opener(path, encoding="utf-8", mode=mode) as f:
            for line in f:
                yield line
    except FileNotFoundError as e:
        log.error(e)
        raise


log_type_opener_stragegy = {
    "": (open, "r"),
    ".gz": (gzip.open, "rt"),
}


def make_report_data(logs: dict[str, list[dict[str, str]]], limit: int | None = None) -> list[dict[str, str | float]]:
    report_data: list[dict[str, str | float]] = []

    all_count = sum(len(v) for _, v in logs.items())
    all_time = sum(float(t["request_time"]) for _, v in logs.items() for t in v)
    for k, v in logs.items():
        if not v:
            continue
        count = len(v)
        times = [float(t["request_time"]) for t in v]
        time_sum = sum(times)
        report_data.append(
            {
                "url": k,
                "count": count,
                "count_perc": round((count / all_count) * 100, 5),
                "time_sum": round(time_sum, 3),
                "time_perc": round((time_sum / all_time) * 100, 3),
                "time_avg": round(statistics.mean(times), 3),
                "time_max": max(times),
                "time_med": round(statistics.median(times), 3),
            }
        )

    if limit:
        report_data = sorted(report_data, key=lambda x: x["time_sum"], reverse=True)
        report_data = report_data[:limit]

    return report_data


def parse_log_record(line: str) -> dict[str, str] | None:
    data = re.search(logline_format, line)
    if data is None:
        return None
    return data.groupdict()


def parse_log_filename(log_filename: str) -> dict[str, str]:
    search_result = re.search(logname_format, log_filename)
    if search_result is None:
        log.error("filename could not be parsed %s", log_filename)
        return {
            "name": log_filename,
            "dt": "",
            "ext": "__broken__",
        }
    res = search_result.groupdict()
    return res | {"filename": log_filename}


def adapt_to_log_file_metadata(dirpath: str, fd: dict[str, str]) -> LogFileMeta:
    full_patch = Path(dirpath).joinpath(fd["filename"])
    dt = datetime.strptime(fd["dt"], "%Y%m%d").date()

    return LogFileMeta(path=full_patch, filename=fd["filename"], dt=dt, ext=fd["ext"])


def get_last_log_file_meta(log_dir: Path) -> LogFileMeta | None:
    if not log_dir.is_dir():
        raise FileNotFoundError("File path was passed. Expected path to directory")

    dirpath, _, filenames = next(os.walk(log_dir), (None, None, []))
    last_founded: LogFileMeta | None = None
    for log_file_meta in filter(lambda x: x["ext"] in allowed_ext, map(parse_log_filename, filenames)):
        if dirpath is None:
            log.error("dirpath not found")
            raise FileNotFoundError()
        f = adapt_to_log_file_metadata(dirpath, log_file_meta)
        if last_founded is None or f.dt > last_founded.dt:
            last_founded = f
    return last_founded


def render_template(data: list[dict[str, str | float]]) -> str:
    with open("report.html", encoding="utf-8", mode="r") as rf:
        tpl = rf.read()
    res = Template(tpl).safe_substitute({"table_json": json.dumps(data)})
    return res


def write_report(path: Path, data: str) -> None:
    with open(path, encoding="utf-8", mode="w+") as w:
        w.write(data)


def aggregate_logs(
    log_line_reader_gen: Generator[str, None, None],
) -> tuple[dict[str, list[dict[str, str]]], list[str], int]:
    logs: dict[str, list[dict[str, str]]] = {}
    errors = []
    for count_read, line in enumerate(log_line_reader_gen):
        m = parse_log_record(line)
        if not m:
            errors.append(line)
            continue

        key = m["request"].strip()
        if key in logs:
            logs[key].append(m)
        else:
            logs[key] = [m]
    return logs, errors, count_read  # pylint: disable=undefined-loop-variable


def check_report_is_exists(report_dir: str, meta: LogFileMeta) -> bool:
    p = Path.cwd().joinpath(report_dir, make_report_name(meta))
    return p.exists()


def make_report_name(meta: LogFileMeta) -> str:
    report_name = meta.dt.strftime("%Y.%m.%d")
    filename = f"report-{report_name}.html"
    return filename


def calc_is_error_treshold(logs_count: int, errors_count: int, treshold: float | None) -> bool:
    if errors_count > logs_count or treshold is None or treshold > 1:
        return False

    ratio = errors_count / logs_count
    return ratio > treshold


def main(cfg: Mapping[str, Any]) -> None:
    try:
        log_file = get_last_log_file_meta(Path.cwd().joinpath(cfg["LOG_DIR"]))
    except ValueError as e:
        log.error(e)
        return
    if log_file is None:
        log.error("Log file not found")
        return
    if check_report_is_exists(cfg["REPORT_DIR"], log_file):
        log.info("Report file already exists")
        return
    if log_file.ext not in log_type_opener_stragegy:
        log.error("File reader stategy not found for extension %s", log_file.ext)
        return

    opener, mode = log_type_opener_stragegy[log_file.ext]
    log_line_reader_gen = log_reader(opener, mode, log_file.path)
    logs, err_lines, total_read = aggregate_logs(log_line_reader_gen)
    if calc_is_error_treshold(total_read, len(err_lines), cfg.get("PARSE_ERR_TRESHOLD_RATIO")):
        log.error("error threshold has been exceeded")
        return

    table_data = make_report_data(logs, cfg["REPORT_SIZE"])
    report = render_template(table_data)
    report_filename = make_report_name(log_file)
    write_report(Path.cwd().joinpath(cfg["REPORT_DIR"], report_filename), report)


def read_config(path: Path) -> dict[str, Any]:
    with open(path, encoding="utf8", mode="r") as cfg:
        config_json: dict[str, Any] = json.load(cfg)
        return config_json


if __name__ == "__main__":
    log.debug("start analyzer")
    parser = argparse.ArgumentParser()
    parser.add_argument("-C", "--config", default=Path.cwd().joinpath("default-config.json"))
    args = parser.parse_args()
    file_config = read_config(args.config)
    app_cfg = ChainMap(file_config, config)
    if app_cfg.get("APP_LOGS"):
        try:
            with open(Path(app_cfg["APP_LOGS"]), encoding="utf-8", mode="wt") as logfile:
                structlog.configure(
                    logger_factory=structlog.WriteLoggerFactory(file=logfile),
                )
        except PermissionError as e:
            log.error("setup app log file %s", e)
    try:
        main(app_cfg)
    except BaseException as e:  # pylint:disable=broad-exception-caught
        log.exception(e)
