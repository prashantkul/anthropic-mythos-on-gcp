# Harness Flow: Security-First Multi-Agent Vulnerability Research

[Back to README](../README.md) | [Architecture](../APPROACH.md)

## Overview

A four-agent pipeline for automated vulnerability discovery, running on a
GCE VM with sandboxed containers. Every agent tool call passes through
multiple security choke points before reaching the sandbox.

## Agent Hierarchy

```mermaid
graph TB
    R[Researcher] -->|task + focus areas| OPUS

    subgraph "Host VM — has GCP credentials"
        OPUS["Mythos Orchestrator\n(Mythos / Opus fallback)\nPlans, delegates, reviews"]
    end

    OPUS -->|run_finder| FINDER
    OPUS -->|run_verifier| VERIFIER
    OPUS -->|run_analyst| ANALYST

    subgraph "Sandbox A — no credentials, no network"
        FINDER["Mythos Finder\n(Mythos)\nReads code, crafts PoC, runs binary"]
    end

    subgraph "Sandbox B — no credentials, no network"
        VERIFIER["Verifier\n(Mythos / Opus)\nReproduces PoC 3/3, 5 criteria"]
    end

    subgraph "Sandbox C — no credentials, no network, read-only"
        ANALYST["Analyst\n(claude-sonnet-4-6)\nRoot cause, CVSS, remediation"]
    end

    style OPUS fill:#0ea5e9,stroke:#333,color:#fff
    style FINDER fill:#22c55e,stroke:#333,color:#fff
    style VERIFIER fill:#eab308,stroke:#333,color:#000
    style ANALYST fill:#3b82f6,stroke:#333,color:#fff
```

## Security Choke Points

Every tool call from a sub-agent passes through three independent choke
points. A call must pass ALL three to execute.

```mermaid
graph LR
    MODEL[Agent Model\nrequests tool call] --> CP1

    CP1["CHOKE POINT 1\nADK Tool Registration\n-----\nAgent only sees allowed tools\nFinder: 6 tools\nVerifier: 2 tools\nAnalyst: 3 tools"]

    CP1 --> CP2

    CP2["CHOKE POINT 2\nSecurityGatewayPlugin\n-----\nbefore_tool_callback\nCommand blocklist\nPath restriction\nRate limiting\nOutput scanning"]

    CP2 --> CP3

    CP3["CHOKE POINT 3\nSandbox Isolation\n-----\n--network=none\n--cap-drop=ALL\nno credentials\nnon-root (UID 1000)\ngVisor runtime"]

    CP3 --> EXEC[docker exec\nin sandbox]

    style CP1 fill:#dc2626,stroke:#333,color:#fff
    style CP2 fill:#dc2626,stroke:#333,color:#fff
    style CP3 fill:#dc2626,stroke:#333,color:#fff
    style EXEC fill:#16a34a,stroke:#333,color:#fff
```

### Choke Point Details

| Choke Point | Layer | What It Blocks | Bypass Requires |
|---|---|---|---|
| **1. ADK Tool Registration** | Framework | Model can't call tools not in its list. Verifier has no `compile_code`. Analyst has no `run_command`. | Bug in ADK framework |
| **2. SecurityGatewayPlugin** | Application | Blocks `curl`, `docker`, `ssh`, `git`, `nc`. Blocks paths outside `/target/` and `/tmp/`. Blocks `169.254.169.254`, `/proc/1/root`, `/var/run/docker.sock`. Redacts credentials in output. | Bug in plugin code |
| **3. Sandbox Isolation** | Infrastructure | No network (can't exfiltrate). No capabilities (can't escape). No credentials (can't access GCP). gVisor intercepts syscalls. | Container runtime vulnerability |

## End-to-End Flow

```mermaid
sequenceDiagram
    participant R as Researcher
    participant O as Mythos (Host)
    participant F as Finder (Sandbox A)
    participant V as Verifier (Sandbox B)
    participant A as Analyst (Sandbox C)
    participant D as Disk

    R->>O: Task + focus areas

    Note over O: For each focus area

    rect rgb(220, 252, 231)
        Note over O,F: FIND PHASE
        O->>O: Create sandbox (docker run --runtime=runsc --network=none)
        O->>F: run_finder(task)
        Note over F: Reads source, crafts PoC, runs binary
        Note over F: SecurityGatewayPlugin validates every tool call
        F->>O: Crash details + PoC at /tmp/poc.bin
        O->>O: Extract PoC bytes from sandbox
        O->>O: Destroy sandbox
    end

    rect rgb(254, 249, 195)
        Note over O,V: VERIFY PHASE
        O->>O: Create fresh sandbox (same image)
        O->>O: Copy PoC bytes to /tmp/poc.bin (stdin pipe)
        O->>V: run_verifier(binary_cmd, crash_type)
        Note over V: Runs binary 3 times, checks 5 criteria
        Note over V: SecurityGatewayPlugin validates every tool call
        V->>O: Verdict (PASS/FAIL) + evidence
        O->>O: Destroy sandbox
    end

    rect rgb(219, 234, 254)
        Note over O,A: ANALYZE PHASE
        O->>O: Create read-only sandbox
        O->>A: run_analyst(crash details)
        Note over A: Reads source, traces root cause
        Note over A: Produces 7-section exploitability report
        A->>O: Report markdown
        O->>D: Auto-save report to results/
        O->>O: Destroy sandbox
    end

    Note over O: Repeat for next focus area

    O->>R: Final assessment summary
```

## Sandbox Security Properties

```mermaid
graph TB
    subgraph "What the Sandbox HAS"
        HAS1[Source code at /target/src]
        HAS2[ASAN binary at /target/bin]
        HAS3[Writable /tmp tmpfs 512MB]
        HAS4[gcc, python3, gdb, xxd]
    end

    subgraph "What the Sandbox DOES NOT HAVE"
        NO1[No network — zero egress/ingress]
        NO2[No GCP credentials — no SA, no metadata]
        NO3[No capabilities — cap-drop ALL]
        NO4[No Docker socket]
        NO5[No host namespaces — separate PID/net/mnt]
        NO6[No root — runs as UID 1000]
        NO7[No persistent storage — destroyed after use]
    end

    style NO1 fill:#dc2626,stroke:#333,color:#fff
    style NO2 fill:#dc2626,stroke:#333,color:#fff
    style NO3 fill:#dc2626,stroke:#333,color:#fff
    style NO4 fill:#dc2626,stroke:#333,color:#fff
    style NO5 fill:#dc2626,stroke:#333,color:#fff
    style NO6 fill:#dc2626,stroke:#333,color:#fff
    style NO7 fill:#dc2626,stroke:#333,color:#fff
    style HAS1 fill:#16a34a,stroke:#333,color:#fff
    style HAS2 fill:#16a34a,stroke:#333,color:#fff
    style HAS3 fill:#16a34a,stroke:#333,color:#fff
    style HAS4 fill:#16a34a,stroke:#333,color:#fff
```

## Trust Boundaries

```mermaid
graph LR
    subgraph "TRUSTED — Host VM"
        HARNESS[Harness Process\nGCP SA via metadata\nCalls Vertex AI\nManages sandboxes]
    end

    subgraph "UNTRUSTED — Sandbox Containers"
        SBX[Agent Workspace\nNo credentials\nNo network\ngVisor isolated]
    end

    HARNESS -->|"docker exec\n(tool calls)"| SBX
    SBX -->|"stdout/stderr\n(tool results)"| HARNESS
    HARNESS -->|"stdin pipe\n(PoC bytes only)"| SBX

    HARNESS -.->|"BLOCKED from sandbox"| META[GCP Metadata\n169.254.169.254]
    HARNESS -->|"accessible from host"| META

    style HARNESS fill:#0ea5e9,stroke:#333,color:#fff
    style SBX fill:#dc2626,stroke:#333,color:#fff
    style META fill:#6b7280,stroke:#333,color:#fff
```

**Data that crosses the trust boundary:**

| Direction | What | How |
|---|---|---|
| Host → Sandbox | Tool call commands | `docker exec` arguments |
| Host → Sandbox | PoC bytes (verifier only) | `docker exec -i sh -c 'cat > /tmp/poc.bin'` |
| Sandbox → Host | Tool call output (stdout/stderr) | `docker exec` return |
| Sandbox → Host | PoC file bytes (finder only) | `docker exec cat /tmp/poc.bin` |

**Data that NEVER crosses:**

| What | Why |
|---|---|
| GCP credentials | Sandbox has no SA, metadata blocked by iptables |
| Network traffic | `--network=none` on all sandboxes |
| Host filesystem | No volume mounts to host paths |
| Docker socket | Never mounted |
| Other sandbox state | Each sandbox is independent, destroyed after use |

## SecurityGatewayPlugin Detail

```mermaid
graph TB
    CALL[Tool Call from Agent] --> CHECK_AGENT{Agent is\nfinder or verifier?}

    CHECK_AGENT -->|No — orchestrator/analyst| ALLOW[Allow — no sandbox rules]
    CHECK_AGENT -->|Yes| CHECK_RATE{Rate limit\nexceeded?}

    CHECK_RATE -->|Yes| DENY1[DENY: rate limit]
    CHECK_RATE -->|No| CHECK_CMD{Command\nin blocklist?}

    CHECK_CMD -->|curl, docker, ssh...| DENY2[DENY: blocked command]
    CHECK_CMD -->|No| CHECK_ARGS{Arguments match\ndeny patterns?}

    CHECK_ARGS -->|169.254.169.254, /proc/1/root...| DENY3[DENY: blocked pattern]
    CHECK_ARGS -->|No| CHECK_PATH{Path outside\n/target/ or /tmp/?}

    CHECK_PATH -->|Yes| DENY4[DENY: path restricted]
    CHECK_PATH -->|No| EXEC[Execute tool call]

    EXEC --> SCAN{Scan output\nfor credentials}
    SCAN -->|Found| REDACT[Redact and return]
    SCAN -->|Clean| RETURN[Return result]

    style DENY1 fill:#dc2626,stroke:#333,color:#fff
    style DENY2 fill:#dc2626,stroke:#333,color:#fff
    style DENY3 fill:#dc2626,stroke:#333,color:#fff
    style DENY4 fill:#dc2626,stroke:#333,color:#fff
    style REDACT fill:#eab308,stroke:#333,color:#000
    style EXEC fill:#16a34a,stroke:#333,color:#fff
    style RETURN fill:#16a34a,stroke:#333,color:#fff
```

## GCE VM Security Context

```mermaid
graph TB
    subgraph "GCP Project — privacy-ml-lab1"
        subgraph "VPC: mythos-vpc (private)"
            subgraph "GCE VM: mythos-harness (no external IP)"
                HARNESS[Harness Process] --> DOCKER[Docker + gVisor]
                DOCKER --> SBX_A[Sandbox A]
                DOCKER --> SBX_B[Sandbox B]
                DOCKER --> SBX_C[Sandbox C]
                IPT[iptables: block metadata\nfrom container subnets]
            end

            FW1[Firewall: deny all ingress]
            FW2[Firewall: allow IAP SSH only]
        end

        NAT[Cloud NAT — egress only]
        SA[mythos-orchestrator-sa\nroles: aiplatform.user\nstorage.objectAdmin\nlogging.logWriter]
        VTXAI[Vertex AI\nClaude Mythos\nClaude Sonnet 4.6]
    end

    HARNESS -->|Private Google Access| VTXAI
    HARNESS -->|VM metadata| SA

    SBX_A -.->|BLOCKED| VTXAI
    SBX_A -.->|BLOCKED by iptables| SA

    style SBX_A fill:#dc2626,stroke:#333,color:#fff
    style SBX_B fill:#dc2626,stroke:#333,color:#fff
    style SBX_C fill:#dc2626,stroke:#333,color:#fff
    style HARNESS fill:#0ea5e9,stroke:#333,color:#fff
    style FW1 fill:#dc2626,stroke:#333,color:#fff
    style IPT fill:#dc2626,stroke:#333,color:#fff
