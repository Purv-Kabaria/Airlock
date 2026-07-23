"""`airlock mcp-config` prints a correct, paste-ready server block for each harness.

The value is removing the silent 'server failed to start' that a wrong interpreter, a relative
config path, or a missing env var produces in an MCP client. So the tests assert the parts that,
if wrong, break the integration: an absolute config path, the referenced env vars carried through,
cwd present only for clients that support it, and http dropping the baked-in principal.
"""

from __future__ import annotations

from pathlib import Path

from airlock.cli.mcp_config import (
    _entry_json,
    build_entry,
    referenced_env_vars,
    render,
)


def _write_config(tmp_path: Path) -> Path:
    p = tmp_path / "airlock.yaml"
    p.write_text(
        "datahub:\n  url: ${DATAHUB_GMS_URL}\n  token: ${DATAHUB_GMS_TOKEN}\n"
        "warehouse:\n  kind: duckdb\n  dsn: ${WAREHOUSE_DSN}\n",
        encoding="utf-8",
    )
    return p


def test_referenced_env_vars_in_first_seen_order(tmp_path) -> None:
    assert referenced_env_vars(_write_config(tmp_path)) == [
        "DATAHUB_GMS_URL",
        "DATAHUB_GMS_TOKEN",
        "WAREHOUSE_DSN",
    ]


def test_config_path_is_absolute(tmp_path) -> None:
    # A client that starts the server from an arbitrary directory (or none) must still find the
    # config. Relative paths are the most common reason an MCP server silently fails to start.
    config = _write_config(tmp_path)
    entry = build_entry(config=config, principal="growth-agent", transport="stdio", env={})
    idx = entry.args.index("--config")
    assert Path(entry.args[idx + 1]).is_absolute()


def test_stdio_bakes_the_principal_http_does_not(tmp_path) -> None:
    config = _write_config(tmp_path)
    stdio = build_entry(config=config, principal="growth-agent", transport="stdio", env={})
    assert "--principal" in stdio.args and "growth-agent" in stdio.args

    http = build_entry(config=config, principal=None, transport="http", env={})
    assert "--principal" not in http.args
    assert "--transport" in http.args and "http" in http.args


def test_claude_desktop_omits_cwd_others_include_it(tmp_path) -> None:
    entry = build_entry(
        config=_write_config(tmp_path), principal="growth-agent", transport="stdio", env={}
    )
    assert "cwd" not in _entry_json("claude-desktop", entry)
    assert "cwd" in _entry_json("claude-code", entry)


def test_claude_code_labels_the_transport(tmp_path) -> None:
    entry = build_entry(
        config=_write_config(tmp_path), principal="growth-agent", transport="stdio", env={}
    )
    assert _entry_json("claude-code", entry)["type"] == "stdio"


def test_render_flags_missing_env_vars(tmp_path) -> None:
    entry = build_entry(
        config=_write_config(tmp_path),
        principal="growth-agent",
        transport="stdio",
        env={"DATAHUB_GMS_URL": ""},
    )
    out = render("claude-code", entry, transport="stdio", missing=["DATAHUB_GMS_URL"])
    assert "DATAHUB_GMS_URL" in out
    assert "unset" in out.lower()


def test_render_claude_code_includes_the_cli_one_liner(tmp_path) -> None:
    entry = build_entry(
        config=_write_config(tmp_path), principal="growth-agent", transport="stdio", env={}
    )
    out = render("claude-code", entry, transport="stdio", missing=[])
    assert "claude mcp add" in out
