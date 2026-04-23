"""Sandboxed code execution MCP server."""
from __future__ import annotations

import ast
import subprocess
from collections.abc import Callable
from tempfile import NamedTemporaryFile
from typing import Any

try:
    from fastmcp import FastMCP
except ImportError:
    FastMCP = None

server = FastMCP("code_exec") if FastMCP is not None else None

_MAX_STDOUT = 8000
_MAX_CODE_CHARS = 8000
_TIMEOUT_SECONDS = 3
_ENABLED = False

_BLOCKED_IMPORTS: frozenset[str] = frozenset({
    "os",
    "subprocess",
    "socket",
    "ctypes",
    "multiprocessing",
    "threading",
    "resource",
    "pathlib",
    "shutil",
    "signal",
    "sys",
})
_BLOCKED_CALLS: frozenset[str] = frozenset({
    "eval",
    "exec",
    "__import__",
    "compile",
    "open",
    "input",
    "breakpoint",
})


def configure_security(config: dict[str, Any]) -> None:
    """Apply code execution policy."""
    global _ENABLED, _MAX_STDOUT, _TIMEOUT_SECONDS, _MAX_CODE_CHARS

    enabled = config.get("code_exec_enabled")
    if isinstance(enabled, bool):
        _ENABLED = enabled

    max_output = config.get("code_exec_max_output_chars")
    if isinstance(max_output, int) and max_output > 0:
        _MAX_STDOUT = max_output

    timeout_seconds = config.get("code_exec_timeout_seconds")
    if isinstance(timeout_seconds, int) and timeout_seconds > 0:
        _TIMEOUT_SECONDS = timeout_seconds

    max_code_chars = config.get("code_exec_max_code_chars")
    if isinstance(max_code_chars, int) and max_code_chars > 0:
        _MAX_CODE_CHARS = max_code_chars


def _validate_code(code: str) -> str | None:
    if len(code) > _MAX_CODE_CHARS:
        return f"Code length exceeds limit ({_MAX_CODE_CHARS} chars)."
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return f"Syntax error: {exc.msg}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                root = name.name.split(".", 1)[0]
                if root in _BLOCKED_IMPORTS:
                    return f"Blocked import: {root}"
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".", 1)[0]
            if root in _BLOCKED_IMPORTS:
                return f"Blocked import: {root}"
        elif isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name and func_name in _BLOCKED_CALLS:
                return f"Blocked call: {func_name}"

    return None


def execute_code(code: str, timeout_seconds: int = 3) -> str:
    """Execute Python code in a subprocess with timeout."""
    if not _ENABLED:
        return "Execution blocked: code_exec tool is disabled by policy."
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be >= 1")
    blocked_reason = _validate_code(code)
    if blocked_reason:
        return f"Execution blocked: {blocked_reason}"

    with NamedTemporaryFile("w", encoding="utf-8", suffix=".py") as script:
        script.write(code)
        script.flush()
        timeout = min(timeout_seconds, _TIMEOUT_SECONDS)
        try:
            proc = subprocess.run(
                ["python3", "-I", "-B", script.name],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env={"PYTHONIOENCODING": "utf-8"},
                cwd="/tmp",
            )
        except subprocess.TimeoutExpired:
            return "Execution timed out."

    output = (proc.stdout or "") + (proc.stderr or "")
    if len(output) > _MAX_STDOUT:
        output = output[:_MAX_STDOUT] + "...(truncated)"
    return output.strip() or "(no output)"


TOOLS: dict[str, Callable[..., object]] = {
    "execute_code": execute_code,
}

if server is not None:
    server.tool(execute_code)


def get_tools() -> dict[str, Callable[..., object]]:
    """Return callable tool map for agent-side local invocation."""
    return dict(TOOLS)
