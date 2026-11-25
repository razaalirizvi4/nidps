import os

from common.env import load_env


def test_load_env_sets_unset_variables_from_dotenv_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NIDPS_TEST_ONLY_VAR=from-dotenv\n")
    monkeypatch.delenv("NIDPS_TEST_ONLY_VAR", raising=False)
    monkeypatch.setattr("common.env.ENV_FILE", env_file)

    load_env()

    assert os.environ["NIDPS_TEST_ONLY_VAR"] == "from-dotenv"


def test_load_env_never_overrides_an_already_exported_value(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("NIDPS_TEST_ONLY_VAR=from-dotenv\n")
    monkeypatch.setenv("NIDPS_TEST_ONLY_VAR", "from-shell")
    monkeypatch.setattr("common.env.ENV_FILE", env_file)

    load_env()

    assert os.environ["NIDPS_TEST_ONLY_VAR"] == "from-shell"


def test_load_env_is_a_no_op_when_no_dotenv_file_exists(tmp_path, monkeypatch):
    monkeypatch.delenv("NIDPS_TEST_ONLY_VAR", raising=False)
    monkeypatch.setattr("common.env.ENV_FILE", tmp_path / "does-not-exist.env")

    load_env()  # must not raise

    assert "NIDPS_TEST_ONLY_VAR" not in os.environ
