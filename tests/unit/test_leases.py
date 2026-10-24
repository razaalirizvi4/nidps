from services.arpmon.leases import parse_dnsmasq_leases


def test_parses_well_formed_lease_lines(tmp_path):
    lease_file = tmp_path / "dnsmasq.leases"
    lease_file.write_text(
        "1760000000 AA:BB:CC:DD:EE:FF 10.10.0.5 laptop 01:aa:bb:cc:dd:ee:ff\n"
        "1760000100 11:22:33:44:55:66 10.10.0.6 phone *\n"
    )

    bindings = parse_dnsmasq_leases(str(lease_file))

    assert bindings == {
        "10.10.0.5": "aa:bb:cc:dd:ee:ff",
        "10.10.0.6": "11:22:33:44:55:66",
    }


def test_skips_malformed_lines(tmp_path):
    lease_file = tmp_path / "dnsmasq.leases"
    lease_file.write_text("garbage\n1760000000 AA:BB:CC:DD:EE:FF 10.10.0.5 laptop *\n")

    bindings = parse_dnsmasq_leases(str(lease_file))

    assert bindings == {"10.10.0.5": "aa:bb:cc:dd:ee:ff"}


def test_missing_file_returns_empty_dict(tmp_path):
    missing = tmp_path / "does-not-exist.leases"
    assert parse_dnsmasq_leases(str(missing)) == {}
