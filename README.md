# Mythos on GCP — Secure Agentic Vulnerability Research

Secure GCP environment for running [Claude Mythos](https://red.anthropic.com/2026/mythos-preview/)
— Anthropic's cybersecurity-focused model — in hardened, sandboxed containers
for autonomous vulnerability discovery.

## What This Is

A multi-agent harness that points Mythos at a C/C++ codebase and autonomously:
1. **Plans** — explores source, identifies attack surface areas
2. **Finds** — crafts PoC inputs that trigger ASAN crashes (parallel)
3. **Verifies** — reproduces each crash 3/3 in a fresh sandbox
4. **Analyzes** — produces structured exploitability reports with CVSS

All execution happens inside Docker + gVisor sandboxes with zero network,
zero credentials, and three independent security choke points per tool call.

Security design informed by [SandboxBench](Prashant_Kulkarni_SadboxBench.pdf)
(Kulkarni et al., SPAR Fall 2025) — our research showing frontier models
exploit 69-77% of container misconfigurations, but defense-in-depth achieves 0%.

## Harnesses

Two implementations, same security model:

| | [Sequential](agentic-harness/) | [Parallel](agentic-harness-parallel/) |
|---|---|---|
| **Planning** | Orchestrator decides per step | Planner agent explores source upfront |
| **Finding** | One finder at a time | N finders simultaneously (ParallelAgent) |
| **Time** | ~20 min (3 areas) | ~8 min (3 areas) |
| **Orchestration** | LLM tool-call loop (ADK) | Deterministic pipeline (ADK ParallelAgent) |
| **Docs** | [README](agentic-harness/README.md) · [FLOW](agentic-harness/FLOW.md) | [README](agentic-harness-parallel/README.md) · [FLOW](agentic-harness-parallel/FLOW.md) |

## Agents

| Agent | Model | Role |
|---|---|---|
| **Planner** | Mythos | Explores source, maps attack surface, outputs focus areas |
| **Finder** (×N) | Mythos | Crafts PoC inputs, triggers ASAN crashes in sandbox |
| **Verifier** | Mythos / Opus | Reproduces PoC 3/3 in fresh sandbox, 5-criteria check |
| **Analyst** | Sonnet 4.6 | Root cause, exploitability, CVSS, remediation |

## Security: Three Choke Points

Every tool call passes through three independent layers:

| Choke Point | Layer | What It Blocks |
|---|---|---|
| **ADK Tool Registration** | Framework | Agent can only call tools in its list |
| **SecurityGatewayPlugin** | Application | Dangerous commands, restricted paths, credentials in output |
| **Sandbox Isolation** | Infrastructure | `--network=none`, `--cap-drop=ALL`, gVisor, non-root |

## Infrastructure

Deployed and validated on GCE VM (`n1-standard-8`, Ubuntu 22.04, no external IP):

| Component | Configuration |
|---|---|
| **Compute** | GCE VM with Docker + gVisor (runsc) |
| **Network** | Private VPC, deny-all ingress, IAP SSH only, Cloud NAT for egress |
| **Sandbox** | `--runtime=runsc --network=none --cap-drop=ALL --user=1000:1000` |
| **Metadata** | iptables blocks containers from `169.254.169.254` |
| **Model access** | Claude via Vertex AI (Anthropic SDK), `anthropic.com` not accessible from sandboxes |
| **Service accounts** | `mythos-orchestrator-sa` (Vertex AI + GCS), `mythos-sandbox-sa` (zero permissions) |

Firecracker/Kata micro-VMs are the recommended upgrade for hardware isolation
(currently blocked by GCE nested virtualization). See [GCE option](options/gce-docker.md).

## Documents

| Document | Description |
|---|---|
| **Harnesses** | |
| [Sequential README](agentic-harness/README.md) | Quick start, architecture, file tree |
| [Sequential FLOW](agentic-harness/FLOW.md) | Flow, security choke points, trust boundaries, ADK details |
| [Parallel README](agentic-harness-parallel/README.md) | Quick start, planner, ParallelAgent, comparison |
| [Parallel FLOW](agentic-harness-parallel/FLOW.md) | Flow, planner phase, per-container closures |
| **Architecture** | |
| [APPROACH.md](APPROACH.md) | 9-ring containment, threat model, GCP controls (VPC-SC, NGFW, on-prem) |
| [SETUP.md](SETUP.md) | GCE VM deployment — verified steps, teardown |
| [Containment Principles](agentic-harness/HARNESS.md) | General security design considerations |
| **Compute Options** | |
| [GCE + Docker](options/gce-docker.md) | Deployed — gVisor, path to Firecracker |
| [GKE](options/gke.md) | Future — team/production, Kata Containers |
| [Cloud Run](options/cloud-run.md) | Not recommended — can't orchestrate sandboxes |
| **References** | |
| [Clearwing Reference](CLEARWING-REFERENCE.md) | Running [Clearwing](https://github.com/Lazarus-AI/clearwing) (LangGraph) inside our containment |
| [SandboxBench Paper](Prashant_Kulkarni_SadboxBench.pdf) | Research: AI agent container escape evaluation (SPAR Fall 2025) |

## Quick Start

```bash
# Deploy GCE VM (see SETUP.md for full steps)
gcloud compute ssh mythos-harness --zone=us-central1-a --tunnel-through-iap

# Sequential harness
cd ~/anthropic-mythos-on-gcp/agentic-harness
docker build -t mythos-canary:latest targets/canary/
uv run mythos-harness targets/canary --runtime runsc

# Parallel harness (with autonomous planner)
cd ~/anthropic-mythos-on-gcp/agentic-harness-parallel
uv run python -m mythos_harness.cli ../agentic-harness/targets/canary --runtime runsc
```

## Validated Results

Both harnesses validated on the canary target (3 planted C memory safety bugs):

- **Sequential**: 4 bugs found (3 planted + 1 discovered), verified, analyzed, reported
- **Parallel**: 3 bugs found via model-planned focus areas, verified, analyzed in ~8 min
- **Token usage**: ~100K (sequential), ~190K (parallel)
- All reports include: primitive characterization, reachability, heap layout, escalation path, CVSS, fix

## References

- [Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/)
- [SandboxBench on UK AISI inspect_evals](https://github.com/UKGovernmentBEIS/inspect_evals)
- [Google ADK Samples](https://github.com/google/adk-samples)
- [Agent Gateway](https://agentgateway.dev/) (future MCP scenarios)
- [Clearwing](https://github.com/Lazarus-AI/clearwing) (LangGraph vuln scanner)
