import json

from training.selfcollected.capture.eve_parser import (
    parse_alert_windows, build_benign_manifest,
)


def _write_eve(tmp_path, events):
    path = tmp_path / "eve.json"
    with path.open("w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")
    return path


def test_parse_alert_windows_only_includes_alert_events(tmp_path):
    eve_path = _write_eve(tmp_path, [
        {"event_type": "flow", "timestamp": "2026-10-22T10:00:00.000000+0000"},
        {"event_type": "alert", "timestamp": "2026-10-22T10:01:00.000000+0000"},
        {"event_type": "alert", "timestamp": "2026-10-22T10:02:00.000000+0000"},
    ])
    windows = parse_alert_windows(eve_path)
    assert len(windows) == 2
    assert windows[0] == ("2026-10-22T10:01:00.000000+0000", "2026-10-22T10:01:00.000000+0000")


def test_parse_alert_windows_returns_empty_list_for_missing_file(tmp_path):
    assert parse_alert_windows(tmp_path / "does_not_exist.json") == []


def test_build_benign_manifest_counts_and_lists_excluded_windows(tmp_path):
    eve_path = _write_eve(tmp_path, [
        {"event_type": "alert", "timestamp": "2026-10-22T10:01:00.000000+0000"},
    ])
    manifest = build_benign_manifest(eve_path, "2026-10-22T10:00:00Z", "2026-10-22T10:10:00Z")
    assert manifest["excluded_count"] == 1
    assert manifest["excluded_windows"] == [
        {"start": "2026-10-22T10:01:00.000000+0000", "end": "2026-10-22T10:01:00.000000+0000"},
    ]
    assert manifest["session_start"] == "2026-10-22T10:00:00Z"
