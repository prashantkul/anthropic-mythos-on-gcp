"""SecurityGatewayPlugin: ADK BasePlugin that intercepts all Mythos tool calls.

Registered on the Runner — applies globally across all agents. Only enforces
sandbox rules on the finder/verifier agents, not the orchestrator or analyst.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

from google.adk.plugins import BasePlugin
from google.adk.tools import BaseTool

SANDBOXED_AGENTS = {"mythos_finder", "verifier"}

COMMAND_DENYLIST = frozenset([
    "curl", "wget", "nc", "netcat", "ncat", "docker", "podman",
    "ssh", "scp", "sftp", "git", "pip", "pip3",
])

ARG_DENYLIST_PATTERNS = [
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"/var/run/docker\.sock"),
    re.compile(r"/proc/1/root"),
    re.compile(r"\$\("),
    re.compile(r"`[^`]+`"),
    re.compile(r"\|\s*(nc|netcat|curl|wget|bash|sh)\b"),
    re.compile(r">\s*/dev/"),
]

CREDENTIAL_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    re.compile(r"gho_[A-Za-z0-9_]{36}"),
    re.compile(r"ya29\.[A-Za-z0-9_-]+"),
]

ALLOWED_PATHS = ("/target/", "/tmp/")

MAX_OUTPUT_BYTES = 102400


class SecurityGatewayPlugin(BasePlugin):

    def __init__(
        self,
        max_calls_per_session: int = 2500,
        name: str = "security_gateway",
    ):
        super().__init__(name)
        self.max_calls = max_calls_per_session
        self.call_count = 0
        self.denied_count = 0
        self.start_time = time.time()

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context,
    ) -> Optional[dict]:
        agent_name = tool_context.agent_name
        if agent_name not in SANDBOXED_AGENTS:
            return None

        self.call_count += 1

        if self.call_count > self.max_calls:
            self.denied_count += 1
            return {"error": f"Session tool call limit exceeded ({self.max_calls})"}

        if tool.name == "run_command":
            result = self._check_command(tool_args)
            if result:
                self.denied_count += 1
                return result

        if tool.name in ("read_file", "analyze_binary"):
            result = self._check_path(tool_args)
            if result:
                self.denied_count += 1
                return result

        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context,
        result: dict,
    ) -> Optional[dict]:
        if tool_context.agent_name not in SANDBOXED_AGENTS:
            return None
        return self._scan_output(result)

    async def on_tool_error_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context,
        error: Exception,
    ) -> Optional[dict]:
        return {"error": f"Tool execution failed: {type(error).__name__}: {error}"}

    def _check_command(self, args: dict) -> Optional[dict]:
        cmd = args.get("command", "")
        tokens = cmd.split()
        if not tokens:
            return {"error": "Empty command"}

        first_word = tokens[0].split("/")[-1]
        if first_word in COMMAND_DENYLIST:
            return {"error": f"Blocked command: {first_word}"}

        for pattern in ARG_DENYLIST_PATTERNS:
            if pattern.search(cmd):
                return {"error": "Blocked pattern in command arguments"}

        return None

    def _check_path(self, args: dict) -> Optional[dict]:
        path = args.get("path", "") or args.get("binary_path", "")
        if not any(path.startswith(p) for p in ALLOWED_PATHS):
            return {"error": f"Path outside allowed directories: {path}"}
        if ".." in path:
            return {"error": "Path traversal not allowed"}
        return None

    def _scan_output(self, result: dict) -> Optional[dict]:
        output = str(result)
        modified = False

        for pattern in CREDENTIAL_PATTERNS:
            cleaned = pattern.sub("[REDACTED]", output)
            if cleaned != output:
                output = cleaned
                modified = True

        if len(output) > MAX_OUTPUT_BYTES:
            output = output[:MAX_OUTPUT_BYTES] + "\n...[truncated]"
            modified = True

        return {"result": output} if modified else None

    async def close(self) -> None:
        elapsed = time.time() - self.start_time
        print(
            f"[security_gateway] Session stats: {self.call_count} calls, "
            f"{self.denied_count} denied, {elapsed:.0f}s elapsed"
        )
