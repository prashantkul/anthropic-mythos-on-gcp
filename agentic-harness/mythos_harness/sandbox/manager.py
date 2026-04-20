"""Sandbox lifecycle: create, exec, read_file, write_file, destroy.

Uses Docker CLI with configurable runtime (runsc for gVisor, kata-fc for
Firecracker micro-VMs). Each sandbox gets --network none and a memory cap.
"""
from __future__ import annotations

import subprocess

from ..config import SANDBOX_CPUS, SANDBOX_MEMORY, SANDBOX_NETWORK, SANDBOX_RUNTIME


def build(dockerfile_dir: str, tag: str) -> str:
    subprocess.run(["docker", "build", "-t", tag, dockerfile_dir], check=True)
    return tag


def create(
    image_tag: str,
    name: str,
    code_volume: str | None = None,
    runtime: str = SANDBOX_RUNTIME,
    network: str = SANDBOX_NETWORK,
    memory: str = SANDBOX_MEMORY,
    cpus: str = SANDBOX_CPUS,
    read_only: bool = True,
) -> str:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)

    cmd = [
        "docker", "run", "-dit",
        "--name", name,
        f"--runtime={runtime}",
        f"--network={network}",
        f"--memory={memory}",
        f"--cpus={cpus}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--tmpfs", "/tmp:rw,nosuid,size=512m",
    ]
    if read_only:
        cmd.append("--read-only")
    if code_volume:
        cmd.extend(["-v", f"{code_volume}:/target:ro"])

    cmd.extend([image_tag, "/bin/bash"])

    r = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"sandbox create failed (exit {r.returncode}): {r.stderr.strip()}")
    return name


def execute(
    container: str,
    command: list[str] | str,
    timeout: int = 180,
    user: str = "1000",
    workdir: str = "/target",
) -> dict[str, str | int]:
    if isinstance(command, str):
        cmd = ["docker", "exec", "-u", user, "-w", workdir, container, "sh", "-c", command]
    else:
        cmd = ["docker", "exec", "-u", user, "-w", workdir, container, *command]

    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": f"Timeout after {timeout}s"}

    stdout = r.stdout.decode("utf-8", errors="replace")[:102400]
    stderr = r.stderr.decode("utf-8", errors="replace")[:10240]
    return {"exit_code": r.returncode, "stdout": stdout, "stderr": stderr}


def read_file(container: str, path: str) -> bytes:
    r = subprocess.run(["docker", "exec", container, "cat", path], capture_output=True)
    return r.stdout if r.returncode == 0 else b""


def write_file(container: str, path: str, content: bytes) -> None:
    """Write bytes into a container via docker exec stdin pipe."""
    r = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", f"cat > {path}"],
        input=content,
        capture_output=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"write_file failed: {r.stderr.decode()}")


def destroy(container: str) -> None:
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)


def image_exists(tag: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", tag], capture_output=True)
    return r.returncode == 0
