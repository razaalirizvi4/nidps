"""FR-2.6: tails Suricata's eve.json alert log. Reads in binary mode and tracks a plain byte
offset (not a text-mode tell()/seek() pair) so there is no ambiguity from newline translation --
each poll() only consumes lines that end in a complete b"\\n", so a line Suricata is still
mid-writing is simply picked up on the next poll().

Also tracks the file's inode and size so log rotation (Suricata's default: rename the old file,
create a new one) is detected rather than silently seeking into the wrong file at a stale byte
offset (I4), and tolerates PermissionError (e.g. running without root against a 0640 root:root
log) the same way it already tolerated FileNotFoundError (I5)."""
from __future__ import annotations

import json
import os


class EveTailer:
    def __init__(self, path: str) -> None:
        self._path = path
        self._offset = 0
        self._inode = None
        self._size = 0

    def poll(self) -> list:
        alerts = []
        try:
            st = os.stat(self._path)
        except (FileNotFoundError, PermissionError):
            return []

        if (self._inode is not None and st.st_ino != self._inode) or self._offset > st.st_size:
            # Rotated (different inode) or truncated/replaced (shrank below our offset).
            self._offset = 0
        self._inode = st.st_ino
        self._size = st.st_size

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
        except (FileNotFoundError, PermissionError):
            return []
        return alerts
