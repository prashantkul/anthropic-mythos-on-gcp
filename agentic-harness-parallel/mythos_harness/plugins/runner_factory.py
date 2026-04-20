"""Runner factory — every ADK Runner in the harness must go through here.

ADK plugins only fire on the Runner they're registered to. The parallel
harness constructs Runners in multiple places (planner, ParallelAgent
workflow, per-finding verifier, per-finding analyst). If any of those
Runners is built without the SecurityGatewayPlugin, its tool calls reach
`docker exec` with Choke Point 2 (command/arg/path/output enforcement)
bypassed.

Routing all Runner construction through `make_runner` makes that bypass
impossible by construction.
"""
from __future__ import annotations

from google.adk.runners import Runner

from .security_gateway import SecurityGatewayPlugin


def make_runner(
    agent,
    *,
    app_name: str,
    session_service,
    gateway: SecurityGatewayPlugin,
    extra_plugins: list | None = None,
) -> Runner:
    plugins = [gateway]
    if extra_plugins:
        plugins.extend(extra_plugins)
    return Runner(
        agent=agent,
        app_name=app_name,
        session_service=session_service,
        plugins=plugins,
    )
