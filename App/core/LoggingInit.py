# App/core/LoggingInit.py
"""
Central logging configuration.

Emits structured JSON — one object per log line — so log aggregators
(ELK, Loki, Datadog, CloudWatch) can parse without regex.

Attaches `request_id` to every log record emitted during a request,
via a ContextVar that `RequestIDMiddleware` sets. ContextVar is the
correct primitive here (not a global) because it is safe under async
concurrency: each request has its own context.
"""

import json
import logging
import os
import sys
from contextvars import ContextVar
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# request_id propagation
# ---------------------------------------------------------------------------
# RequestIDMiddleware should call `set_request_id(req_id)` on entry and
# `set_request_id("-")` on exit. The JsonFormatter reads this value for
# every log record.
# ---------------------------------------------------------------------------
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


def set_request_id(req_id: str) -> None:
    """Set the current request's ID in the context."""
    request_id_var.set(req_id)


def get_request_id() -> str:
    """Read the current request's ID."""
    return request_id_var.get()


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    """
    Emit one JSON object per log record.

    Schema:
        {
            "ts": "2026-09-11T09:58:23.123456Z",
            "level": "INFO",
            "logger": "App.core.Connector",
            "msg": "...",
            "request_id": "abc-123" | "-",
            "exc": "Traceback..."   # only if record.exc_info
            ...plus any keys passed via extra={...}
        }
    """

    # Attributes set by logging itself that we do not want to duplicate
    _RESERVED = frozenset({
        "name", "msg", "args", "levelname", "levelno", "pathname",
        "filename", "module", "exc_info", "exc_text", "stack_info",
        "lineno", "funcName", "created", "msecs", "relativeCreated",
        "thread", "threadName", "processName", "process", "taskName",
        "message",
    })

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S.%fZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }

        # Traceback, if any
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        # Anything passed via extra={...}
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and key not in payload:
                # Ensure value is JSON-serializable
                try:
                    json.dumps(value)
                    payload[key] = value
                except (TypeError, ValueError):
                    payload[key] = repr(value)

        return json.dumps(payload, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
def setup_core_logging(log_path: Optional[str] = None) -> logging.Logger:
    """
    Configure the root logger.

    Priority for log path:
        1. explicit argument
        2. LOG_PATH env var
        3. "logs" (relative to cwd)
    """
    # Resolve log directory
    if log_path:
        log_dir_path = log_path
    elif "LOG_PATH" in os.environ:
        log_dir_path = os.environ["LOG_PATH"]
    else:
        log_dir_path = "logs"

    log_dir = Path(log_dir_path)
    log_file = log_dir / "core.log"

    # Log level
    log_level_str = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    # Root logger
    root = logging.getLogger()
    root.setLevel(log_level)
    root.handlers.clear()

    formatter = JsonFormatter()

    # ---- File handler (best-effort; containers may have RO filesystems) ----
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=10 * 1024 * 1024,   # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as e:
        # Read-only FS, permission denied, disk full — do not crash the app
        # over logging. Log to stderr about the failure after console handler
        # is added below.
        file_handler = None
        _file_error = e
    else:
        _file_error = None

    # ---- Console handler (stdout) ----
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    # ---- Startup diagnostics ----
    if _file_error is not None:
        root.warning(
            "File logging disabled (filesystem not writable)",
            extra={"error": str(_file_error), "log_dir": str(log_dir)},
        )
    root.info(
        "Core logging initialized",
        extra={
            "log_file": str(log_file) if file_handler else None,
            "log_level": log_level_str,
        },
    )

    return root


# ---------------------------------------------------------------------------
# Module-level setup (runs once on import)
# ---------------------------------------------------------------------------
core_logger = setup_core_logging()


def get_core_logger(name: str = "App.core") -> logging.Logger:
    """Get a logger for core modules."""
    return logging.getLogger(name)


def get_module_logger(module_name: str) -> logging.Logger:
    """Get a logger for any module."""
    return logging.getLogger(f"App.{module_name}")