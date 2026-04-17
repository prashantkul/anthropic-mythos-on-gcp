"""Mythos tool definitions. Plain functions — ADK auto-wraps as FunctionTool.

All tools delegate to sandbox.manager for execution inside the container.
The SecurityGatewayPlugin validates every call before it reaches these functions.
"""
from __future__ import annotations

from ..sandbox import manager as sandbox

_CURRENT_CONTAINER: str | None = None


def set_container(name: str) -> None:
    global _CURRENT_CONTAINER
    _CURRENT_CONTAINER = name


def _container() -> str:
    if not _CURRENT_CONTAINER:
        raise RuntimeError("No sandbox container set. Call set_container() first.")
    return _CURRENT_CONTAINER


def read_file(path: str) -> str:
    """Read a file from the target codebase.

    Args:
        path: Absolute path within the sandbox (must be under /target/ or /tmp/).
    """
    result = sandbox.execute(_container(), ["cat", path])
    if result["exit_code"] != 0:
        return f"Error reading {path}: {result['stderr']}"
    return result["stdout"]


def run_command(command: str) -> str:
    """Run a shell command in the analysis sandbox.

    Args:
        command: Shell command to execute. Some commands are blocked by security policy.
    """
    result = sandbox.execute(_container(), command, timeout=180)
    output = result["stdout"]
    if result["stderr"]:
        output += f"\nSTDERR:\n{result['stderr']}"
    if result["exit_code"] != 0:
        output += f"\n[exit code: {result['exit_code']}]"
    return output


def search_code(pattern: str, file_glob: str = "*") -> str:
    """Search for regex patterns in the target codebase.

    Args:
        pattern: Regex pattern to search for.
        file_glob: File glob to filter (e.g., '*.c', '*.h'). Defaults to all files.
    """
    result = sandbox.execute(
        _container(),
        ["grep", "-rn", "--include", file_glob, pattern, "/target/"],
        timeout=60,
    )
    if result["exit_code"] == 1:
        return "No matches found."
    return result["stdout"]


def compile_code(build_command: str, working_dir: str = "/target") -> str:
    """Compile target code in the sandbox.

    Args:
        build_command: Build command (e.g., 'make', 'gcc -fsanitize=address -o test poc.c').
        working_dir: Working directory within the sandbox. Must be under /target/.
    """
    result = sandbox.execute(_container(), build_command, timeout=300, workdir=working_dir)
    output = result["stdout"]
    if result["stderr"]:
        output += f"\n{result['stderr']}"
    if result["exit_code"] != 0:
        output += f"\n[build failed, exit code: {result['exit_code']}]"
    return output


def analyze_binary(path: str, tool: str = "strings") -> str:
    """Run static analysis on a binary in the sandbox.

    Args:
        path: Path to the binary within the sandbox.
        tool: Analysis tool to use. One of: strings, objdump, readelf, file, nm.
    """
    allowed = ("strings", "objdump", "readelf", "file", "nm")
    if tool not in allowed:
        return f"Tool must be one of: {', '.join(allowed)}"
    result = sandbox.execute(_container(), [tool, path], timeout=60)
    return result["stdout"] or result["stderr"]


def list_files(path: str = "/target", recursive: bool = False) -> str:
    """List files in a directory within the sandbox.

    Args:
        path: Directory path within the sandbox.
        recursive: If True, list recursively (max depth 3).
    """
    if recursive:
        cmd = ["find", path, "-maxdepth", "3", "-type", "f"]
    else:
        cmd = ["ls", "-la", path]
    result = sandbox.execute(_container(), cmd, timeout=30)
    return result["stdout"]


FINDER_TOOLS = [read_file, run_command, search_code, compile_code, analyze_binary, list_files]
VERIFIER_TOOLS = [run_command, read_file]
ANALYST_TOOLS = [read_file, search_code, list_files]
