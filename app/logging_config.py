"""
Structured logging configuration.

When LOG_FORMAT=json, all log output is emitted as single-line JSON objects
suitable for SIEM ingestion (Splunk, Datadog, ELK).

When LOG_FORMAT=text (default), standard Python logging format is used.
"""
import json
import logging
import traceback
from datetime import datetime, timezone

# Attributes present on every LogRecord — excluded from "extra" output
_BUILTIN_ATTRS = frozenset({
    "args", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg",
    "name", "pathname", "process", "processName", "relativeCreated",
    "stack_info", "thread", "threadName", "taskName",
})


class JsonFormatter(logging.Formatter):
    """Single-line JSON log formatter."""

    def format(self, record: logging.LogRecord) -> str:
        record.message = record.getMessage()
        log_obj: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }
        extras = {
            k: v for k, v in record.__dict__.items()
            if k not in _BUILTIN_ATTRS and not k.startswith("_")
        }
        if extras:
            log_obj["extra"] = extras
        if record.exc_info and record.exc_info[1]:
            log_obj["exception"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(log_obj, default=str)


def configure_logging(log_format: str = "text") -> None:
    """Configure the agent_trust and uvicorn loggers.

    Call this at module level in main.py, before any log statements execute.
    """
    if log_format != "json":
        return  # Keep Python/uvicorn defaults for text mode

    formatter = JsonFormatter()

    for name in ("agent_trust", "uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        if name == "agent_trust":
            logger.setLevel(logging.INFO)
