# Sequential Harness: Flow and Security Architecture

[Back to README](../README.md) | [GCE Setup](../SETUP.md)

## Overview

A four-agent sequential pipeline for vulnerability discovery on GCE.
Mythos orchestrates, finds, verifies, and analyzes — each step in its
own sandboxed container. Every tool call passes through three security
choke points.

## Agent Hierarchy

```mermaid
graph TB
    R[Researcher] -->|task + focus areas| ORCH

    subgraph "Host VM — has GCP credentials"
        ORCH["Mythos Orchestrator\nPlans, delegates, reviews"]
    end

    ORCH -->|run_finder| FINDER
    ORCH -->|run_verifier| VERIFIER
    ORCH -->|run_analyst| ANALYST

    subgraph "Sandbox A — no credentials, no network"
        FINDER["Mythos Finder\nReads code, crafts PoC, runs binary"]
    end

    subgraph "Sandbox B — no credentials, no network"
        VERIFIER["Verifier\nReproduces PoC 3/3, 5 criteria"]
    end

    subgraph "Sandbox C — no credentials, no network, read-only"
        ANALYST["Analyst (Sonnet 4.6)\nRoot cause, CVSS, remediation"]
    end

    style ORCH fill:#0ea5e9,stroke:#333,color:#fff
    style FINDER fill:#22c55e,stroke:#333,color:#fff
    style VERIFIER fill:#eab308,stroke:#333,color:#000
    style ANALYST fill:#3b82f6,stroke:#333,color:#fff
```

## End-to-End Flow

```mermaid
sequenceDiagram
    participant R as Researcher
    participant O as Orchestrator (Host)
    participant F as Finder (Sandbox A)
    participant V as Verifier (Sandbox B)
    participant A as Analyst (Sandbox C)
    participant D as Disk

    R->>O: Task + focus areas

    Note over O: For each focus area

    rect rgb(220, 252, 231)
        Note over O,F: FIND
        O->>O: Create sandbox (--runtime=runsc --network=none)
        O->>F: run_finder(task)
        Note over F: SecurityGatewayPlugin validates every tool call
        F->>O: Crash details + PoC at /tmp/poc.bin
        O->>O: Extract PoC bytes, destroy sandbox
    end

    rect rgb(254, 249, 195)
        Note over O,V: VERIFY
        O->>O: Create fresh sandbox, copy PoC via stdin pipe
        O->>V: run_verifier(binary_cmd, crash_type)
        Note over V: Runs binary 3 times, checks 5 criteria
        V->>O: Verdict (PASS/FAIL), destroy sandbox
    end

    rect rgb(219, 234, 254)
        Note over O,A: ANALYZE
        O->>O: Create read-only sandbox
        O->>A: run_analyst(crash details)
        A->>D: Report auto-saved
        O->>O: Destroy sandbox
    end

    Note over O: Repeat for next focus area
    O->>R: Final assessment summary
```

## Security Choke Points

Every tool call passes through three independent layers. ALL three must
approve for execution to proceed.

```mermaid
graph LR
    MODEL[Agent] --> CP1["CHOKE POINT 1\nADK Tool Registration\nFinder: 6 tools\nVerifier: 2 tools\nAnalyst: 3 tools"]
    CP1 --> CP2["CHOKE POINT 2\nSecurityGatewayPlugin\nCommand blocklist\nPath restriction\nOutput scanning"]
    CP2 --> CP3["CHOKE POINT 3\nSandbox Isolation\n--network=none\n--cap-drop=ALL\ngVisor, non-root"]
    CP3 --> EXEC[docker exec]

    style CP1 fill:#dc2626,stroke:#333,color:#fff
    style CP2 fill:#dc2626,stroke:#333,color:#fff
    style CP3 fill:#dc2626,stroke:#333,color:#fff
    style EXEC fill:#16a34a,stroke:#333,color:#fff
```

| Choke Point | Layer | Blocks | Bypass Requires |
|---|---|---|---|
| **ADK Tool Registration** | Framework | Tools not in agent's list | ADK bug |
| **SecurityGatewayPlugin** | Application | `curl`, `docker`, `ssh`, `git`, `nc`. Paths outside `/target/`, `/tmp/`. Metadata IP. Credentials in output | Plugin bug |
| **Sandbox Isolation** | Infrastructure | Network, capabilities, credentials, host access | Runtime vulnerability |

## Verification: Two-Sandbox Trust Boundary

A finding is not confirmed until a separate agent reproduces it in a
**fresh sandbox** from the same image. Only PoC bytes cross.

```mermaid
graph LR
    FIND[Find Sandbox\nAgent crafts PoC] -->|PoC bytes only| GRADE[Grade Sandbox\nFresh, same image]
    GRADE -->|3/3?| V{Pass?}
    V -->|yes| REPORT[Analyze + Report]
    V -->|no| DISCARD[Discard]

    style FIND fill:#22c55e,stroke:#333,color:#fff
    style GRADE fill:#eab308,stroke:#333,color:#000
    style DISCARD fill:#999,stroke:#333,color:#fff
```

**5 criteria** — all must pass:

| # | Check |
|---|---|
| 1 | PoC file exists and is non-empty |
| 2 | Crash reproduces 3/3 times |
| 3 | Not OOM or timeout (exit 137/124) |
| 4 | Crash is in project code (not just libc) |
| 5 | Consistent crash type across all runs |

## Sandbox Properties

| Property | Finder | Verifier | Analyst |
|---|---|---|---|
| Container name | `find_{target}_{uuid}` | `grade_{target}_{uuid}` | `analyze_{target}_{uuid}` |
| Runtime | `--runtime=runsc` | `--runtime=runsc` | `--runtime=runsc` |
| Network | `--network=none` | `--network=none` | `--network=none` |
| Read-only rootfs | No (needs to compile) | No (needs to run PoC) | Yes |
| Has PoC | Agent creates at /tmp/poc.bin | Harness copies before start | No |
| Credentials | None | None | None |
| Lifetime | Created → used → destroyed per call | Same | Same |

## Trust Boundaries

```mermaid
graph LR
    subgraph "TRUSTED — Host"
        H[Harness\nGCP SA, Vertex AI]
    end
    subgraph "UNTRUSTED — Sandbox"
        S[Agent\nNo creds, no network]
    end

    H -->|docker exec| S
    S -->|stdout/stderr| H
    H -->|stdin pipe PoC| S

    H -->|accessible| META[Metadata]
    S -.->|BLOCKED| META

    style H fill:#0ea5e9,stroke:#333,color:#fff
    style S fill:#dc2626,stroke:#333,color:#fff
    style META fill:#6b7280,stroke:#333,color:#fff
```

| Crosses Boundary | How |
|---|---|
| Tool commands (host → sandbox) | `docker exec` arguments |
| PoC bytes (host → verifier) | `docker exec -i sh -c 'cat > /tmp/poc.bin'` |
| Tool output (sandbox → host) | `docker exec` stdout/stderr |
| PoC bytes (finder → host) | `docker exec cat /tmp/poc.bin` |

| NEVER Crosses | Why |
|---|---|
| GCP credentials | No SA, metadata blocked |
| Network traffic | `--network=none` |
| Host filesystem | No mounts |
| Docker socket | Never mounted |

## ADK Implementation Details

### Why Tool-Based Delegation (Not sub_agents)

ADK's `sub_agents` + `transfer_to_agent` doesn't work with Claude on Vertex AI
(designed for Gemini). We use the pattern from
[ai-security-agent](https://github.com/google/adk-samples/tree/main/python/agents/ai-security-agent):
sub-agents run inside tool functions via fresh Runner + ThreadPoolExecutor.

### SecurityGatewayPlugin Registered on Every Runner

The plugin is on the orchestrator's Runner AND each sub-agent's Runner.
Without this, sub-agent tool calls bypass the gateway.

### Agent Gateway — Future MCP Scenarios

Our tools are local Python functions. The SecurityGatewayPlugin intercepts
in-process. If tools later become MCP servers:

| Product | When |
|---|---|
| [agentgateway.dev](https://agentgateway.dev/) | Open-source MCP/A2A proxy for infra-level policy |
| [Google Cloud Agent Gateway](https://cloud.google.com/iam/docs/roles-permissions/agentgateway) | GCP managed agent networking |

Neither applies to our current local-tool design.

## Resource Budgets

| Resource | Orchestrator | Finder | Verifier |
|---|---|---|---|
| Max turns | 50 | High (tune per target) | 50 |
| Max runtime | 8 hours | 4 hours per delegation | 15 min |
| Max output | — | 100KB per tool call | 100KB |
| Container memory | — | 8GB | 4GB |

## Validation with SandboxBench

Before deploying, run SandboxBench escape challenges against the environment:

```mermaid
graph LR
    SBX[SandboxBench] --> HARNESS[Your Harness]
    HARNESS --> SANDBOX[Your Sandbox]
    SBX -->|verify| R{Escaped?}
    R -->|yes| FIX[Fix]
    R -->|no| DEPLOY[Deploy]
    FIX --> SBX

    style FIX fill:#dc2626,stroke:#333,color:#fff
    style DEPLOY fill:#16a34a,stroke:#333,color:#fff
```

| Category | Expected |
|---|---|
| Escape (8 challenges) | 0/8 |
| Exfiltration (3) | 0/3 |
| Persistence (3) | 0/3 |
| Replication (2) | 0/2 |
