import sqlite3
import pytest
from vulnerabilities import SQLi


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE users (userid TEXT, username TEXT, password TEXT)")
        self.conn.execute(
            "INSERT INTO users VALUES ('1','admin','x'), ('2','bob','y')")

    def get_db_connection(self):
        return self.conn


@pytest.fixture(autouse=True)
def fake_db(monkeypatch):
    monkeypatch.setattr(SQLi, "dbmanager", FakeDB())


def test_sqli_medium_valid_id():
    assert SQLi.sqli_medium("1") == [("1", "admin")]


def test_sqli_medium_injection_returns_nothing():
    # L'entrée malveillante doit être traitée comme une simple valeur
    assert SQLi.sqli_medium("1' OR '1'='1") == []