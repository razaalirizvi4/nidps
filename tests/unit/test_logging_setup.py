import json
import logging

from common.logging_setup import configure_logging


def test_log_line_is_valid_json_with_expected_fields(capsys):
    logger = configure_logging("test-component", level=logging.INFO)
    logger.info("hello world")

    captured = capsys.readouterr()
    line = captured.out.strip().splitlines()[-1]
    payload = json.loads(line)

    assert payload["level"] == "INFO"
    assert payload["component"] == "test-component"
    assert payload["message"] == "hello world"
