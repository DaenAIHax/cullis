"""Tests for structured JSON logging."""
import json
import logging

from app.logging_config import JsonFormatter, configure_logging


def test_json_formatter_basic():
    """JsonFormatter produces valid JSON with required keys."""
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="agent_trust", level=logging.INFO, pathname="test.py",
        lineno=1, msg="hello %s", args=("world",), exc_info=None,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "agent_trust"
    assert parsed["message"] == "hello world"
    assert "timestamp" in parsed


def test_json_formatter_with_exception():
    """Exception info is serialized in the JSON output."""
    formatter = JsonFormatter()
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="agent_trust", level=logging.ERROR, pathname="test.py",
        lineno=1, msg="error occurred", args=(), exc_info=exc_info,
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert "exception" in parsed
    assert "ValueError" in parsed["exception"]
    assert "boom" in parsed["exception"]


def test_json_formatter_single_line():
    """JSON output must be a single line (no embedded newlines in message)."""
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="agent_trust", level=logging.INFO, pathname="test.py",
        lineno=1, msg="line1\nline2", args=(), exc_info=None,
    )
    output = formatter.format(record)
    # json.dumps produces single-line by default
    assert "\n" not in output


def test_configure_logging_text_is_noop():
    """configure_logging('text') does not modify handlers."""
    logger = logging.getLogger("agent_trust")
    handlers_before = list(logger.handlers)
    configure_logging("text")
    assert logger.handlers == handlers_before


def test_configure_logging_json_installs_formatter():
    """configure_logging('json') installs JsonFormatter on agent_trust logger."""
    configure_logging("json")
    logger = logging.getLogger("agent_trust")
    assert len(logger.handlers) > 0
    assert isinstance(logger.handlers[0].formatter, JsonFormatter)
    # Cleanup — restore default
    logger.handlers.clear()
