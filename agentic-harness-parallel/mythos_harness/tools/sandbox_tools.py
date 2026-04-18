"""Tool factory: creates per-container tool sets for parallel execution.

Each finder/verifier/analyst gets its own tools bound to its own container
via closure. No global state — safe for parallel execution.
"""
from __future__ import annotations

from ..sandbox import manager as sandbox


def create_finder_tools(container_name: str) -> list:
    """Create finder tools bound to a specific container."""

    def read_file(path: str) -> str:
        """Read a file from the target codebase.

        Args:
            path: Absolute path within the sandbox (must be under /target/ or /tmp/).
        """
        result = sandbox.execute(container_name, ["cat", path])
        if result["exit_code"] != 0:
            return f"Error reading {path}: {result['stderr']}"
        return result["stdout"]

    def run_command(command: str) -> str:
        """Run a shell command in the analysis sandbox.

        Args:
            command: Shell command to execute.
        """
        result = sandbox.execute(container_name, command, timeout=180)
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
            file_glob: File glob to filter (e.g., '*.c'). Defaults to all files.
        """
        result = sandbox.execute(
            container_name,
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
            working_dir: Working directory within the sandbox.
        """
        result = sandbox.execute(container_name, build_command, timeout=300, workdir=working_dir)
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
        result = sandbox.execute(container_name, [tool, path], timeout=60)
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
        result = sandbox.execute(container_name, cmd, timeout=30)
        return result["stdout"]

    return [read_file, run_command, search_code, compile_code, analyze_binary, list_files]


def create_verifier_tools(container_name: str) -> list:
    """Create verifier tools bound to a specific container."""
    all_tools = create_finder_tools(container_name)
    return [t for t in all_tools if t.__name__ in ("run_command", "read_file")]


def create_analyst_tools(container_name: str) -> list:
    """Create analyst tools bound to a specific container."""
    all_tools = create_finder_tools(container_name)
    return [t for t in all_tools if t.__name__ in ("read_file", "search_code", "list_files")]
