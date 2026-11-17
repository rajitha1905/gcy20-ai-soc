import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    """Point every module at a throwaway data directory."""
    from pipeline import config
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "INCOMING_FILE", tmp_path / "incoming" / "eve.json")
    monkeypatch.setattr(config, "QUEUE_FILE", tmp_path / "queue" / "events.jsonl")
    monkeypatch.setattr(config, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "soc.db")
    monkeypatch.setattr(config, "BLOCKLIST_FILE", tmp_path / "response" / "blocklist.txt")
    monkeypatch.setattr(config, "QUARANTINE_FILE", tmp_path / "response" / "quarantine.txt")
    monkeypatch.setattr(config, "EXPORT_DIR", tmp_path / "exports")
    monkeypatch.setattr(config, "COLLECTOR_FAULT_FLAG", tmp_path / "state" / "collector.fault")
    from pipeline import collector, engine
    monkeypatch.setattr(collector, "OFFSET_FILE", tmp_path / "state" / "collector.offset")
    monkeypatch.setattr(collector, "SEQ_FILE", tmp_path / "state" / "collector.seq")
    monkeypatch.setattr(engine, "OFFSET_FILE", tmp_path / "state" / "engine.offset")
    config.ensure_dirs()
    return tmp_path


@pytest.fixture(scope="session", autouse=True)
def trained_model():
    from pipeline import config
    if not (config.MODEL_DIR / "model.joblib").exists():
        from models import train
        train.main()
