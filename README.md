# GCP Mythos Sandbox

Secure GCP environment for exploring [Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/) — Anthropic's cybersecurity-focused model capable of autonomous zero-day discovery and exploit development.

## Overview

This project provides the architecture and deployment scripts for running Mythos in a hardened, containerized environment on Google Cloud Platform. The security design is directly informed by [SandboxBench](Prashant_Kulkarni_SadboxBench.pdf) (Kulkarni et al., SPAR Fall 2025), a comprehensive evaluation framework that demonstrated frontier models can exploit 69-77% of container misconfigurations.

Mythos is accessed exclusively via **Vertex AI** — there is no direct access to Anthropic APIs. This is itself a security control: all model interactions are governed by GCP IAM, VPC Service Controls, and Cloud Audit Logs.

## Documents

| Document | Description |
|----------|-------------|
| [APPROACH.md](APPROACH.md) | Architecture overview: threat model, 9-ring defense-in-depth, comparison table, VPC-SC, Cloud NGFW, source code ingestion, implementation plan |
| [Option A: Cloud Run](options/cloud-run.md) | gVisor always on, zero idle cost, 24h max runtime |
| [Option B: GCE + Firecracker](options/gce-docker.md) | **Recommended.** Firecracker micro-VM, hardware isolation, full flexibility |
| [Option C: GKE](options/gke.md) | Most defense-in-depth, scales to teams, highest complexity |
| [HARNESS.md](agentic-harness/HARNESS.md) | Harness components: Agent Gateway, tool definitions, session management, validation with SandboxBench |
| [HARNESS-DESIGN.md](agentic-harness/HARNESS-DESIGN.md) | Multi-agent harness architecture: Opus orchestrator + Mythos worker, ADK vs LangGraph implementations, framework comparison |
| [SETUP.md](SETUP.md) | GCE VM setup: VPC, firewall, Docker + gVisor, metadata blocking, harness install, teardown |
| [SandboxBench Paper](Prashant_Kulkarni_SadboxBench.pdf) | Research: "SandboxBench: A Comprehensive Evaluation Framework for AI Agent Containment" (Kulkarni et al., SPAR Fall 2025) |

## Security Architecture

9-ring defense-in-depth model. Container hardening is the **foundation** — every outer ring operates independently.

| Ring | Control | What It Stops |
|------|---------|---------------|
| 0 | **Container Hardening** | Privilege escalation, filesystem persistence, capability abuse |
| 1 | **Micro-VM / gVisor** | Kernel-level escapes — Firecracker/Kata micro-VM (GCE/GKE), gVisor (Cloud Run) |
| 2 | **Egress Proxy (Squid)** | Data exfiltration, direct Anthropic API access, DNS tunneling |
| 3 | **VPC Firewall + NAT** | Metadata service access, lateral movement, inbound attacks |
| 4 | **Cloud NGFW / Palo Alto** | Encrypted C2, exploit delivery, covert channels |
| 5 | **VPC Service Controls** | Cross-project data theft, stolen credential abuse |
| 6 | **SecurityGatewayPlugin** | ADK BasePlugin — command blocklist, path restriction, rate limiting, output scanning |
| 7 | **On-Prem Proxy** | Policy violations missed by cloud controls, shadow IT |
| 8 | **Monitoring & Audit** | Undetected breaches, compliance gaps |

## Key Design Decisions

### Vertex AI Only (No Direct Anthropic API)

All Mythos interactions go through Vertex AI on GCP. `anthropic.com` is explicitly
blocked in the proxy allowlist. This ensures every API call is subject to GCP IAM,
VPC-SC perimeter checks, and Cloud Audit Logs.

### Source Code via Cloud Source Repos / GCS

The sandbox never clones from GitHub/GitLab directly. Repos are mirrored into Cloud
Source Repositories or staged in GCS — both within the VPC-SC perimeter. The sandbox
receives code as a read-only volume mount. No git CLI, SSH keys, or PATs in the sandbox.

### GCE + Docker Recommended (for now)

Simplest mental model (one VM, one micro-VM sandbox, one proxy), full flexibility,
strongest self-managed isolation with Firecracker micro-VMs (hardware-enforced via
KVM). gVisor intercepts syscalls in userspace but still shares the host kernel — a
model that finds kernel zero-days needs hardware isolation. Enterprise controls
(Rings 2-8) are identical across all compute options.

### Multi-Agent Harness with Google ADK (Recommended)

The harness uses a multi-agent architecture where **Claude Opus** orchestrates and
**Claude Mythos** executes vulnerability research. Both run on Vertex AI.

| Agent | Role | Tool Access |
|---|---|---|
| **Opus** (Orchestrator) | Plans investigation, delegates tasks, reviews findings, writes reports | GCS, BigQuery, delegate-to-Mythos. No sandbox access |
| **Mythos** (Worker) | Reads code, runs commands, builds exploits | Sandbox only. All tools execute via `docker exec` through Agent Gateway |

**ADK with SecurityGatewayPlugin** — an ADK `BasePlugin` intercepts all Mythos
tool calls through `before_tool_callback` (validation, blocklists, rate limiting)
and `after_tool_callback` (output scanning, credential redaction). Native Vertex AI
integration, all-Google ecosystem. [Agent Gateway](https://agentgateway.dev/)
available for future MCP scenarios. LangGraph as alternative for built-in checkpointing.

See [HARNESS-DESIGN.md](agentic-harness/HARNESS-DESIGN.md) for full comparison, code
examples for both ADK and LangGraph, and the security analysis.

## SandboxBench Findings

From the [research paper](Prashant_Kulkarni_SadboxBench.pdf):

- **77% escape rate** on misconfigured Docker containers — Mythos is far more capable
- **0% escape rate** with defense-in-depth — validates the ring-based approach
- **0% autonomous discovery** in hard mode — but Mythos finds zero-days autonomously
- **Single-layer defense: 67-70% vulnerable. Multi-layer: 0%**

> "Containment must not rely on model alignment alone."
> — SandboxBench, Section 5.2.2

## References

- [Claude Mythos Preview Technical Report](https://red.anthropic.com/2026/mythos-preview/)
- [SandboxBench Paper (local)](Prashant_Kulkarni_SadboxBench.pdf)
- [SandboxBench on UK AISI inspect_evals](https://github.com/UKGovernmentBEIS/inspect_evals) (PR #713, #745, #789)
- [GCP VPC Service Controls](https://cloud.google.com/vpc-service-controls/docs/overview)
- [Cloud NGFW Enterprise (Palo Alto)](https://cloud.google.com/firewall/docs/about-firewalls)
- [GKE Sandbox (gVisor)](https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods)
- [Container-Optimized OS](https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits)
- [Private Service Connect](https://cloud.google.com/vpc/docs/private-service-connect)
- [Cloud Source Repositories Mirroring](https://cloud.google.com/source-repositories/docs/mirroring-a-github-repository)
