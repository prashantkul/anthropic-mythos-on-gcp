# Parallel Harness: Flow and Security Architecture

[Back to README](README.md) | [GCE Setup](../SETUP.md)

## Overview

A five-phase parallel pipeline for vulnerability discovery on GCE.
Mythos plans the investigation autonomously, spawns N parallel finders,
then verifies and analyzes each finding sequentially. Every tool call
passes through three security choke points.

## Agent Hierarchy

```mermaid
graph TB
    R[Researcher] -->|target| PLAN

    subgraph "Host VM — has GCP credentials"
        PLAN["Planner\n(Mythos)\nExplores source, identifies focus areas"]
    end

    PLAN -->|N focus areas| PAR

    subgraph PAR [ParallelAgent — simultaneous]
        F0["Finder 0\nSandbox A"]
        F1["Finder 1\nSandbox B"]
        FN["Finder N\nSandbox N"]
    end

    PAR -->|findings| SEQ[Sequential per finding]

    subgraph SEQ [Verify + Analyze]
        V["Verifier\nFresh Sandbox"]
        A["Analyst (Sonnet 4.6)\nRead-only Sandbox"]
    end

    style PLAN fill:#0ea5e9,stroke:#333,color:#fff
    style F0 fill:#22c55e,stroke:#333,color:#fff
    style F1 fill:#22c55e,stroke:#333,color:#fff
    style FN fill:#22c55e,stroke:#333,color:#fff
    style V fill:#eab308,stroke:#333,color:#000
    style A fill:#3b82f6,stroke:#333,color:#fff
```

## End-to-End Flow

```mermaid
sequenceDiagram
    participant R as Researcher
    participant P as Planner (Host)
    participant F as Finders (Parallel)
    participant V as Verifier
    participant A as Analyst
    participant D as Disk

    R->>P: Target source code

    rect rgb(219, 234, 254)
        Note over P: PHASE 1: PLAN
        P->>P: Create read-only sandbox
        P->>P: Explore source, map attack surface
        P->>P: Output N focus areas with reasoning
        P->>P: Destroy sandbox
    end

    rect rgb(220, 252, 231)
        Note over P,F: PHASE 2: FIND (parallel)
        P->>F: Create N sandboxes, launch ParallelAgent
        Note over F: All N finders run simultaneously
        Note over F: Each has own sandbox + tools via closure
        F->>P: Crash details + PoCs
        P->>P: Extract PoC bytes, destroy all finder sandboxes
    end

    Note over P: For each finding with PoC:

    rect rgb(254, 249, 195)
        Note over P,V: PHASE 3: VERIFY
        P->>P: Create fresh sandbox, copy PoC via stdin
        P->>V: Run verifier (3/3, 5 criteria)
        V->>P: Verdict, destroy sandbox
    end

    rect rgb(219, 234, 254)
        Note over P,A: PHASE 4: ANALYZE
        P->>P: Create read-only sandbox
        P->>A: Produce exploitability report
        A->>D: Auto-save report
        P->>P: Destroy sandbox
    end

    P->>R: Token summary + report paths
```

## Security Choke Points

Same three independent layers as the sequential harness. ALL must
approve for execution.

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
| **SecurityGatewayPlugin** | Application | Dangerous commands, restricted paths, metadata IP, credentials in output | Plugin bug |
| **Sandbox Isolation** | Infrastructure | Network, capabilities, credentials, host access | Runtime vulnerability |

## Verification: Two-Sandbox Trust Boundary

Same as sequential — fresh sandbox, only PoC bytes cross, 5 criteria.

| # | Check |
|---|---|
| 1 | PoC file exists and is non-empty |
| 2 | Crash reproduces 3/3 times |
| 3 | Not OOM or timeout (exit 137/124) |
| 4 | Crash is in project code |
| 5 | Consistent crash type across runs |

## Sandbox Properties

| Property | Planner | Finder (×N) | Verifier | Analyst |
|---|---|---|---|---|
| Container name | `plan_{target}` | `find_{target}_{i}` | `grade_{target}_{i}` | `analyze_{target}_{i}` |
| Network | `--network=none` | `--network=none` | `--network=none` | `--network=none` |
| Read-only | Yes | No | No | Yes |
| Parallel | No (one) | Yes (N simultaneous) | No (sequential) | No (sequential) |
| Credentials | None | None | None | None |
| Has PoC | No | Agent creates | Harness copies | No |

## Trust Boundaries

```mermaid
graph LR
    subgraph "TRUSTED — Host"
        H[Pipeline\nGCP SA, Vertex AI]
    end
    subgraph "UNTRUSTED — Sandboxes"
        S[Agents\nNo creds, no network]
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

## ADK Implementation Details

### ParallelAgent Works with Claude

Verified: ADK's `ParallelAgent` runs Claude sub-agents simultaneously.
Unlike `sub_agents` + `transfer_to_agent` (Gemini-only), `ParallelAgent`
directly executes agents without requiring transfer.

### Per-Container Tool Closures

No global `_CURRENT_CONTAINER`. Each finder gets tools bound to its own
container via closure:

```python
def create_finder_tools(container_name: str) -> list:
    def read_file(path: str) -> str:
        return sandbox.execute(container_name, ["cat", path])
    ...
    return [read_file, run_command, ...]
```

Safe for parallel execution — N finders, N containers, N independent
tool sets.

### Planner Runs by Default

The planner agent explores source code and determines focus areas
autonomously. Use `--skip-planner` to use config-defined areas instead.

### PoC Extraction Fallback

Checks multiple paths (`/tmp/poc.bin`, `/tmp/poc`, etc.) then
`find /tmp -name '*.bin'` as fallback. Models sometimes save PoCs
to unexpected paths.

## Resource Budgets

| Resource | Planner | Finder (×N) | Verifier | Analyst |
|---|---|---|---|---|
| Max turns | 100 | High (tune per target) | 50 | 100 |
| Container memory | 8GB | 8GB | 4GB | 8GB |
| Parallel instances | 1 | N (limited by VM RAM) | 1 | 1 |

**VM sizing**: N parallel finders × 8GB = total sandbox RAM. n1-standard-8
(~30GB) supports 3 parallel finders comfortably.

## Validation with SandboxBench

Same as sequential — run all escape/exfiltration/persistence/replication
challenges. Expected: 0/8 escape, 0/3 exfil, 0/3 persist, 0/2 replicate.
