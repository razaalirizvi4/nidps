"""FR-2.6: tails Suricata's eve.json alert log. Reads in binary mode and tracks a plain byte
offset (not a text-mode tell()/seek() pair) so there is no ambiguity from newline translation --
each poll() only consumes lines that end in a complete b"\\n", so a line Suricata is still
mid-writing is simply picked up on the next poll()."""
from __future__ import annotations

import json


class EveTailer:
    def __init__(self, path: str) -> None:
        self._path = path
        self._offset = 0

    def poll(self) -> list:
        alerts = []
        try:
            with open(self._path, "rb") as fh:
                fh.seek(self._offset)
                for raw_line in fh:
                    if not raw_line.endswith(b"\n"):
                        break
                    self._offset += len(raw_line)
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event_type") == "alert":
                        alerts.append(event)
        except FileNotFoundError:
            return []
        return alerts
