"""One structured JSON log format shared by every NIDPS service, so journald/systemd output
is consistently parseable."""
from __future__ import annotations

import json
import logging
import sys

from common.schemas import utc_now_iso


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": utc_now_iso(),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(component: str, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(component)
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.propagate = False
    return logger
