import json
import os

import pytest

from services.sigbridge.eve_tailer import EveTailer


def test_poll_returns_only_alert_events_and_tracks_offset(tmp_path):
    path = tmp_path / "eve.json"
    alert_event = {
        "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 2001219, "severity": 2, "action": "allowed"},
    }
    other_event = {"event_type": "flow", "src_ip": "10.0.0.5"}
    path.write_text(json.dumps(other_event) + "\n" + json.dumps(alert_event) + "\n")

    tailer = EveTailer(str(path))
    assert tailer.poll() == [alert_event]
    assert tailer.poll() == []

    new_alert = {
        "event_type": "alert", "src_ip": "10.0.0.9", "dest_ip": "5.6.7.8",
        "alert": {"signature_id": 1, "severity": 1, "action": "drop"},
    }
    with open(path, "a") as fh:
        fh.write(json.dumps(new_alert) + "\n")

    assert tailer.poll() == [new_alert]


def test_poll_returns_empty_list_for_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    assert EveTailer(str(missing)).poll() == []


def test_poll_ignores_malformed_json_lines(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text("not-json\n")
    assert EveTailer(str(path)).poll() == []


def test_poll_handles_log_rotation_without_losing_or_garbling_alerts(tmp_path):
    path = tmp_path / "eve.json"
    old_alert = {
        "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 1, "severity": 1, "action": "allowed"},
    }
    path.write_text(json.dumps(old_alert) + "\n")

    tailer = EveTailer(str(path))
    assert tailer.poll() == [old_alert]
    assert tailer._offset > 0

    # Simulate Suricata's rotation: rename-away (delete here, since nothing references the old
    # path anymore) and create a brand NEW, smaller file at the same path with a different inode.
    os.remove(path)
    new_alert = {
        "event_type": "alert", "src_ip": "9.9.9.9", "dest_ip": "8.8.8.8",
        "alert": {"signature_id": 2, "severity": 3, "action": "drop"},
    }
    path.write_text(json.dumps(new_alert) + "\n")

    assert tailer.poll() == [new_alert]


def test_poll_recovers_when_file_is_truncated_below_tracked_offset(tmp_path):
    path = tmp_path / "eve.json"
    alert = {
        "event_type": "alert", "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature_id": 1, "severity": 1, "action": "allowed"},
    }
    path.write_text(json.dumps(alert) + "\n" * 3)

    tailer = EveTailer(str(path))
    tailer._offset = 10_000  # far beyond the actual (small) file size

    assert tailer.poll() == [alert]  # re-reads from the start rather than raising


def test_poll_returns_empty_list_on_permission_error(tmp_path, monkeypatch):
    path = tmp_path / "eve.json"
    path.write_text("{}\n")
    tailer = EveTailer(str(path))

    def _raise_permission_error(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(os, "stat", _raise_permission_error)

    assert tailer.poll() == []
