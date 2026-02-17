"""Unit tests for MCP server tool modules."""
from __future__ import annotations

from uuid import uuid4

import pytest

from aegis.testbed.mcp_servers.code_exec_server import configure_security as configure_code_exec
from aegis.testbed.mcp_servers.code_exec_server import execute_code
from aegis.testbed.mcp_servers.database_server import (
    configure_security as configure_database,
)
from aegis.testbed.mcp_servers.database_server import insert_record, query_db
from aegis.testbed.mcp_servers.email_server import (
    clear_inbox,
    read_inbox,
    send_email,
)
from aegis.testbed.mcp_servers.email_server import (
    configure_security as configure_email,
)
from aegis.testbed.mcp_servers.filesystem_server import (
    configure_security as configure_filesystem,
)
from aegis.testbed.mcp_servers.filesystem_server import (
    delete_file,
    list_directory,
    read_file,
    write_file,
)
from aegis.testbed.mcp_servers.http_server import configure_security as configure_http
from aegis.testbed.mcp_servers.http_server import fetch_url, post_request


@pytest.fixture(autouse=True)
def _reset_mcp_security_policies() -> None:
    configure_code_exec(
        {
            "code_exec_enabled": False,
            "code_exec_timeout_seconds": 3,
            "code_exec_max_output_chars": 8000,
            "code_exec_max_code_chars": 8000,
        }
    )
    configure_database({"database_max_rows": 1000, "database_timeout_seconds": 2.0})
    configure_email({"email_max_inbox_items": 200, "email_max_body_chars": 20_000})
    configure_filesystem(
        {
            "filesystem_safe_root": "/tmp/aegis_fs",
            "filesystem_max_read_bytes": 1_048_576,
            "filesystem_max_write_bytes": 1_048_576,
        }
    )
    configure_http(
        {
            "http_allowlist": ["localhost", "127.0.0.1", "::1"],
            "http_block_private_networks": True,
            "http_timeout_seconds": 8,
            "http_max_response_bytes": 8192,
        }
    )


def test_filesystem_roundtrip_and_listing():
    filename = f"test-{uuid4().hex}.txt"
    write_file(filename, "hello")
    assert read_file(filename) == "hello"
    assert filename in list_directory(".")
    assert delete_file(filename) == f"Deleted {filename}"


def test_filesystem_blocks_path_traversal():
    with pytest.raises(ValueError, match="safe root"):
        read_file("../../etc/passwd")


def test_email_server_send_and_read():
    clear_inbox()
    send_email("alice@example.com", "Subject", "Body")
    inbox = read_inbox()
    assert len(inbox) == 1
    assert inbox[0]["to"] == "alice@example.com"


def test_database_insert_and_select():
    record_text = f"row-{uuid4().hex}"
    insert_record(record_text)
    rows = query_db(
        "SELECT data FROM records ORDER BY id DESC LIMIT 1"
    )
    assert rows
    assert rows[0]["data"] == record_text


def test_code_exec_runs_python():
    configure_code_exec({"code_exec_enabled": True})
    output = execute_code("print('ok')")
    assert output == "ok"


def test_code_exec_disabled_by_default():
    output = execute_code("print('ok')")
    assert "disabled by policy" in output.lower()


def test_http_fetch_returns_error_text_when_unreachable():
    output = fetch_url("http://127.0.0.1:1")
    assert "error" in output.lower()


def test_http_blocks_non_allowlisted_target():
    output = fetch_url("https://example.com")
    assert "request blocked" in output.lower()


# ------------------------------------------------------------------
# Day 2: additional MCP server tests
# ------------------------------------------------------------------


def test_database_blocks_non_select_queries():
    """query_db must reject DROP TABLE statements."""
    with pytest.raises(ValueError, match="SELECT"):
        query_db("DROP TABLE records")


def test_database_blocks_insert_via_query():
    """query_db must reject INSERT statements."""
    with pytest.raises(ValueError, match="SELECT"):
        query_db("INSERT INTO records(data) VALUES ('hack')")


def test_http_post_returns_error_text_when_unreachable():
    """post_request to an unreachable host should return error text, not raise."""
    output = post_request("http://127.0.0.1:1", {"key": "value"})
    assert "error" in output.lower()


def test_email_clear_inbox():
    """clear_inbox should empty the inbox after sending."""
    clear_inbox()
    send_email("bob@example.com", "Test", "Body")
    assert len(read_inbox()) == 1
    result = clear_inbox()
    assert result == "Inbox cleared"
    assert len(read_inbox()) == 0
