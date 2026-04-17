# Secure GCP Environment for Claude Mythos Exploration

## 1. Context and Motivation

Claude Mythos Preview is Anthropic's cybersecurity-focused model capable of autonomous
zero-day vulnerability discovery and exploit development. Its reported capabilities include
developing working Firefox exploits 181 times (vs. 2 for prior models) and achieving full
control flow hijack on 10 fully patched OSS-Fuzz targets.

This document defines the architecture for a secure GCP environment to explore Mythos
for code-related vulnerability research. The goal is maximum flexibility for exploration
with zero risk of uncontained impact.

**Access model**: Mythos is accessed exclusively via **Vertex AI** on GCP. There is no
direct access to Anthropic APIs. This is itself a security control -- all model
interactions stay within the GCP project boundary and are subject to VPC Service
Controls, IAM policies, and audit logging native to GCP.

### Why SandboxBench Findings Matter Here

Our prior research with SandboxBench (Kulkarni et al., SPAR Fall 2025) evaluated
frontier models (GPT-5, Gemini 2.5 Pro, GPT-4o-mini) against 27 container security
challenges across Docker and Kubernetes. Key findings that directly inform this
architecture:

| SandboxBench Finding | Implication for Mythos Environment |
|---|---|
| Frontier models achieve 69-77% escape rate on Docker challenges at medium difficulty | Mythos is significantly more capable -- assume near-100% escape on misconfigured containers |
| Direct exploitation paths always succeed (privileged, docker_socket, capabilities, shared_pid) | These misconfigurations are not theoretical; they WILL be exploited |
| Defense-in-depth drops vulnerability from 67-70% to 0% | Single-layer security is insufficient; must layer multiple controls |
| Hard mode (no hints) = 0% success for current models | This gap will not hold for Mythos, which autonomously discovers zero-days |
| K8s RBAC misconfigurations exploitable (40% success, 100% on easy challenges) | Kubernetes adds attack surface; RBAC must be minimal |
| Social engineering achieves 80% success on baseline servers | Not directly applicable but reinforces: assume the agent is adversarial |
| Models show "capability overhang" -- they know more than they demonstrate | Design containment for capabilities beyond what benchmarks measure |

The critical insight from SandboxBench Section 5.2.2 (Defensive Implications):
**"Containment must not rely on model alignment alone. Organizations should assume
adversaries will eventually deploy capable, unaligned models against their infrastructure."**

With Mythos, we are not deploying an unaligned model -- but we are deploying a model
whose core capability is finding and exploiting vulnerabilities. The containment must
be robust against the model's own capabilities, not just external threats.

## 2. Threat Model

### What Mythos Can Do (Assume Worst Case)

- Discover and exploit unknown container runtime vulnerabilities
- Chain multiple low-severity issues into full escape
- Identify and exploit cloud metadata endpoints for credential theft
- Exfiltrate data via DNS tunneling, covert channels, or proxy bypass
- Establish persistence via cron, backdoor users, startup scripts
- Laterally move to adjacent services if network access exists
- Self-replicate by spawning new containers (if Docker socket exposed)
- Abuse Vertex AI API access to pivot to other GCP services (if credentials reachable)

### What We Must Prevent

1. **Escape to host** -- agent breaks out of container to underlying VM/node
2. **Credential theft** -- agent accesses GCP metadata service or SA keys
3. **Data exfiltration** -- agent sends sensitive data to external endpoints
4. **Lateral movement** -- agent reaches other GCP services or networks
5. **Persistence** -- agent survives container restart or establishes backdoors
6. **Uncontrolled GCP access** -- agent uses GCP credentials beyond intended scope
7. **Direct API bypass** -- agent contacts Anthropic APIs directly, circumventing Vertex AI controls
8. **Source code leakage** -- agent exfiltrates target source code to external repositories or endpoints

### What We Must Allow

1. Code analysis and compilation within the sandbox
2. Controlled execution of target software
3. Read access to GCS buckets (target code, datasets)
4. Write access to GCS buckets (results, reports)
5. BigQuery access for logging and analysis
6. Pull images from Artifact Registry
7. Vertex AI API access for Mythos model calls (orchestrator only)
8. Read access to mirrored source repositories (via Cloud Source Repositories or GCS)

## 3. Architecture Options Comparison

### 3.1 High-Level Architecture (Common to All Options)

The architecture is organized as concentric security rings. Container hardening is
foundational (innermost ring). Each outer ring adds defense-in-depth that operates
independently -- if an inner ring is breached, outer rings still contain the impact.

```mermaid
graph LR
    S[Sandbox Container] -->|all egress| P[Squid Proxy]
    P --> NGFW[Cloud NGFW]
    NGFW --> NAT[Cloud NAT]
    NAT --> VPN[Cloud VPN]
    VPN --> ONPREM[On-Prem Proxy]
    ONPREM --> Internet((Internet))

    style S fill:#ff6b6b,stroke:#333,color:#fff
    style P fill:#ffd93d,stroke:#333
    style NGFW fill:#e67e22,stroke:#333,color:#fff
    style ONPREM fill:#2c3e50,stroke:#333,color:#fff
```

```mermaid
graph LR
    GW[Agent Gateway] -->|via PSC| VTXAI[Vertex AI / Mythos]
    GW --> GCS[(GCS)]
    GW --> BQ[(BigQuery)]
    CSR[Cloud Source Repos] -->|read-only volume| S[Sandbox]

    S -.->|BLOCKED| VTXAI
    S -.->|BLOCKED| META[Metadata 169.254.169.254]

    style S fill:#ff6b6b,stroke:#333,color:#fff
    style GW fill:#6bcb77,stroke:#333
    style META fill:#999,stroke:#333,color:#fff
```

### 3.2 Credential and API Access Model

The sandbox container has NO credentials and NO network path to GCP APIs. All GCP
interactions are mediated by the orchestrator, which itself is behind an Agent Gateway
that enforces policy. Mythos is accessed exclusively via Vertex AI -- there is no
direct path to Anthropic APIs from any component.

```mermaid
graph LR
    O[Orchestrator] -->|prompts via PSC| VTXAI[(Vertex AI)]
    VTXAI -->|tool calls| GW[Agent Gateway]
    GW -->|filtered calls| O
    O -->|execute| S[Sandbox]
    S -->|output| O

    O --> GCS[(GCS)]
    O --> BQ[(BigQuery)]
    O --> AR[(Artifact Registry)]
    O --> CSR[(Cloud Source Repos)]

    S -.->|BLOCKED: no SA, no metadata| GCS
    S -.->|BLOCKED| VTXAI
    S -.->|BLOCKED: not in allowlist| ANTH[anthropic.com]

    style S fill:#ff6b6b,stroke:#333,color:#fff
    style GW fill:#6bcb77,stroke:#333
    style O fill:#3498db,stroke:#333,color:#fff
    style ANTH fill:#999,stroke:#333,color:#fff
```

**Why no direct Anthropic API access**: Routing through Vertex AI means all model
interactions are governed by GCP IAM, VPC-SC, audit logs, and org policies. Direct
Anthropic API calls would bypass all of these controls. The Squid proxy allowlist
does NOT include `anthropic.com` -- this is intentional.

### 3.3 Option Comparison Table

| Dimension | **Cloud Run** | **GCE + Docker** | **GKE** |
|---|---|---|---|
| **Isolation mechanism** | gVisor (built-in, always on) | **Firecracker micro-VM** (recommended) or Kata Containers. Each sandbox gets own kernel | **Kata Containers** via RuntimeClass (recommended) or GKE Sandbox (gVisor) |
| **Escape difficulty** | Hardest managed option. No SSH, no node access, gVisor intercepts syscalls | **Hardest self-managed**. Micro-VM escape requires breaking KVM hypervisor (hardware-enforced) | Hard. Kata micro-VM + namespace + NetworkPolicy. gVisor fallback available |
| **Metadata service risk** | None. Cloud Run abstracts credentials internally | HIGH if not blocked. Must add iptables rule on host. Easy to forget | Medium. Must configure NetworkPolicy. Workload Identity disables legacy endpoint |
| **Egress control** | VPC connector + Cloud NAT. L7 filtering needs sidecar proxy | Squid on host or sidecar. iptables for L3. Full flexibility | Cilium L3/L4 NetworkPolicy + Squid pod for L7 domain filtering |
| **VPC Service Controls** | Supported. Cloud Run service within perimeter | Supported. VM within perimeter | Supported. GKE cluster within perimeter |
| **Cloud NGFW / Palo Alto** | Via VPC connector — traffic passes through NGFW endpoint | Direct — all egress from VM subnet inspected by NGFW | Direct — all egress from node subnet inspected by NGFW |
| **On-prem proxy routing** | Via VPC connector → Cloud VPN | Direct — Cloud NAT → VPN → on-prem proxy | Direct — Cloud NAT → VPN → on-prem proxy |
| **Vertex AI access** | SA attached to service → Vertex AI API via Private Google Access | Orchestrator on host → Vertex AI via Private Service Connect | Orchestrator pod with Workload Identity → Vertex AI via PSC |
| **GCS access** | Orchestrator SA: `roles/storage.objectAdmin` | Same — orchestrator on host has SA, sandbox is isolated | Same — orchestrator pod has Workload Identity, sandbox pod does not |
| **BigQuery access** | Orchestrator SA: `roles/bigquery.dataEditor` + `jobUser` | Same | Same |
| **Artifact Registry** | Orchestrator SA: `roles/artifactregistry.reader` | Same — host pulls images, sandbox can't | Same — node SA pulls images |
| **Source repo access** | Orchestrator pulls from CSR/GCS, mounts into container | Same — orchestrator on host clones from CSR, copies into sandbox | Same — init container or orchestrator pod clones from CSR |
| **Nested containers** | No. Cannot run Docker-in-Docker | Yes. Can run target software in sub-containers | Yes, via DinD sidecar or Kaniko |
| **Max runtime** | Jobs: 24h. HTTP: 60min | Unlimited | Unlimited |
| **Max resources** | 8 vCPU, 32GB RAM | Any machine type. GPUs available | Any node pool. GPUs available |
| **Persistent storage** | Ephemeral only (tmpfs) | Persistent disk on VM | PVC with Persistent Disk |
| **Operational burden** | Near zero. Fully managed | Medium. Patch COS, manage Docker, VM lifecycle | High. Cluster upgrades, node pools, K8s manifests, RBAC |
| **Monthly cost (idle)** | $0 | ~$30 (e2-standard-4, auto-stopped) | ~$100+ (cluster fee + nodes) |
| **Monthly cost (active, 8h/day)** | ~$15-40 (per-second billing) | ~$50-80 (fixed VM) | ~$120-180 (cluster + nodes) |
| **Setup complexity** | Low (~30 min) | Medium (~1 hour) | High (~2-3 hours) |
| **Enterprise controls setup** | +1 hour (VPC-SC, NGFW, VPN) | +1 hour (same) | +1.5 hours (same + K8s policies) |
| **Attack surface** | Minimal. No SSH, no node, no K8s API | VM is reachable if container escapes | K8s API server, etcd, kubelet, RBAC — each is attack surface |
| **SandboxBench escape applicability** | 0/8 escape challenges apply (gVisor blocks all) | 0/8 with Firecracker micro-VM (own kernel). 5/8 apply if using runc without hardening | 0/8 with Kata micro-VM. 6/8 Docker + 6/6 K8s apply if misconfigured |
| **Best for** | Short-lived, bounded analysis tasks | Interactive, long-running exploration. Single researcher | Team use, multi-tenant, production workloads |

### 3.4 Detailed Option Architectures

Each option is documented in its own file with architecture diagrams, security
details, cost estimates, and SandboxBench applicability:

- **[Option A: Cloud Run](options/cloud-run.md)** — Strongest default isolation (gVisor always on), zero idle cost, but limited to 24h runtime and 32GB RAM
- **[Option B: GCE + Firecracker](options/gce-docker.md)** (Recommended) — Simplest mental model, full flexibility, strongest self-managed isolation with Firecracker micro-VMs
- **[Option C: GKE](options/gke.md)** — Most defense-in-depth, scales to teams, but highest complexity and cost

## 4. Security Controls Deep Dive

### 4.0 Layered Defense Model

Container hardening is the **foundation**. Everything else is an outer ring. If you
can only implement one thing, implement Ring 0. Each successive ring operates
independently -- a breach of an inner ring does not compromise an outer ring.

SandboxBench demonstrated that single-layer defense allows 67-70% exploitation,
while multi-layer defense achieves 0%. For Mythos, we apply defense-in-depth
across eight layers:

```mermaid
graph LR
    R0["Ring 0\nContainer Hardening\n(FOUNDATION)"] --> R1["Ring 1\nMicro-VM / gVisor"]
    R1 --> R2["Ring 2\nEgress Proxy"]
    R2 --> R3["Ring 3\nVPC + Firewall"]
    R3 --> R4["Ring 4\nCloud NGFW"]
    R4 --> R5["Ring 5\nVPC-SC Perimeter"]
    R5 --> R6["Ring 6\nAgent Gateway"]
    R6 --> R7["Ring 7\nOn-Prem Proxy"]
    R7 --> R8["Ring 8\nMonitoring"]

    style R0 fill:#c0392b,color:#fff
    style R1 fill:#e74c3c,color:#fff
    style R2 fill:#e67e22,color:#fff
    style R3 fill:#f39c12,color:#fff
    style R4 fill:#d35400,color:#fff
    style R5 fill:#8e44ad,color:#fff
    style R6 fill:#2ecc71,color:#fff
    style R7 fill:#2c3e50,color:#fff
    style R8 fill:#3498db,color:#fff
```

| Ring | Layer | Key Controls |
|------|-------|-------------|
| 0 | Container Hardening | Non-root, read-only rootfs, drop ALL caps, seccomp, no privilege escalation |
| 1 | Micro-VM / gVisor | Firecracker or Kata micro-VM (GCE/GKE), gVisor user-space kernel (Cloud Run). Own kernel per sandbox, no Docker socket |
| 2 | Egress Proxy | Squid domain allowlist, `anthropic.com` denied, proxy handles DNS, request logging |
| 3 | VPC + Firewall | Deny-all ingress, block metadata `169.254.169.254`, Cloud NAT only, IAP for SSH |
| 4 | Cloud NGFW | L7 DPI, IPS/IDS signatures, TLS inspection, URL filtering, DNS security |
| 5 | VPC-SC Perimeter | Ingress from orchestrator SA + corp IPs only, deny all cross-project egress |
| 6 | Agent Gateway | Tool call filtering, rate limiting, content scanning, Vertex AI audit trail |
| 7 | On-Prem Proxy | Corporate DLP, CASB visibility, SOC/SIEM integration via Cloud VPN |
| 8 | Monitoring | Cloud Audit Logs, VPC Flow Logs, NGFW logs, proxy logs, alerting policies |

### 4.1 Ring 0 — Container Hardening (Foundation)

This is the innermost, most critical layer. If every outer ring fails, this must hold.

| Control | Setting | What It Prevents |
|---|---|---|
| Non-root user | `USER 1000` / `runAsUser: 1000` | Prevents writing to system paths, binding privileged ports |
| Read-only rootfs | `--read-only` / `readOnlyRootFilesystem: true` | Prevents persistence via cron, startup scripts, backdoor users |
| Drop all capabilities | `--cap-drop=ALL` / `drop: ["ALL"]` | Prevents `mount`, `insmod`, `ptrace`, raw sockets |
| No privilege escalation | `--security-opt=no-new-privileges` / `allowPrivilegeEscalation: false` | Prevents SUID/SGID exploits |
| Seccomp profile | `--security-opt seccomp=default` / `seccompProfile: RuntimeDefault` | Blocks dangerous syscalls (`init_module`, `mount`, `ptrace`) |
| No Docker socket | Never mount `/var/run/docker.sock` | Prevents container spawning, image backdooring, host access |
| No host namespaces | `--pid=container` / `hostPID: false`, `hostNetwork: false` | Prevents `/proc/1/root` escape, network sniffing |
| Tmpfs for writable dirs | `--tmpfs /tmp:rw,noexec,nosuid,size=512m` | Writable space without rootfs modification, size-limited, noexec |

### 4.2 Ring 1 — Runtime Isolation (Micro-VM / gVisor)

gVisor interposes a user-space kernel between the container and the host kernel,
intercepting syscalls in userspace. This is strong — but gVisor itself runs on the
host kernel. A model that finds zero-days in Firefox and develops JIT heap sprays
could plausibly find a gVisor escape, at which point the host kernel is exposed.

**Micro-VMs** (Firecracker, Kata Containers) give each sandbox its own kernel,
its own memory space, and a minimal hypervisor attack surface. A gVisor escape
inside a micro-VM only reaches the guest kernel — the host is still protected
by hardware virtualization (KVM/VMX).

| Runtime | Isolation Level | Overhead | Best For |
|---|---|---|---|
| **runc** (default) | Namespace/cgroup only | None | Never use for Mythos — all SandboxBench escapes apply |
| **runsc (gVisor)** | User-space kernel | 5-20% CPU | Cloud Run (default, no choice). Baseline for GKE |
| **Firecracker** | Micro-VM, own kernel, ~125ms boot | ~5MB per VM | **GCE recommended** — strongest isolation, minimal footprint, Rust VMM |
| **Kata Containers** | OCI-compatible micro-VM | Higher than Firecracker | **GKE recommended** — drop-in via RuntimeClass, works with K8s ecosystem |
| **gVisor + Firecracker** | Nested: gVisor inside micro-VM | Combined | Maximum isolation — two independent boundaries. For highest-risk workloads |

**Per-platform recommendation:**
- **Cloud Run**: gVisor (always on, no configuration needed, no alternative)
- **GCE**: **Firecracker** (strongest isolation, ~125ms boot, Rust VMM). Alternative: Kata Containers
- **GKE**: **Kata Containers** via RuntimeClass (OCI-compatible, drop-in replacement for GKE Sandbox). Alternative: GKE Sandbox (gVisor)

**Why micro-VM over gVisor for GCE/GKE:**

| Scenario | gVisor | Micro-VM (Firecracker/Kata) |
|---|---|---|
| Mythos finds a container runtime bug | Escape reaches host kernel | Escape reaches guest kernel inside VM — host protected by hypervisor |
| Mythos exploits a syscall handler | gVisor Sentry is the target — single boundary | Guest kernel is the target — hypervisor is second boundary |
| Unknown zero-day in isolation layer | gVisor is ~200K LoC Go — smaller than Linux kernel but still attack surface | KVM hypervisor is battle-tested, hardware-enforced (VMX/VT-x) |
| Performance | 5-20% CPU overhead | ~5% CPU, ~5MB memory, ~125ms boot (Firecracker) |

### 4.3 Ring 2 — Egress Proxy

Adapted from the SandboxBench Squid proxy configuration. The sandbox container's
network namespace routes ALL traffic through the proxy. The container has no direct
DNS resolver -- the proxy handles DNS resolution.

**Critical control**: `anthropic.com` is NOT in the allowlist. All Mythos model
access goes through Vertex AI APIs on `googleapis.com`, accessed only by the
orchestrator. This prevents the sandbox from bypassing Vertex AI controls.

| Category | Allowed Domains | Purpose |
|---|---|---|
| Package repos | `.pypi.org`, `files.pythonhosted.org` | Python packages |
| Package repos | `.debian.org`, `.ubuntu.com` | System packages |
| Package repos | `.npmjs.org`, `registry.npmjs.org` | Node.js packages (if needed) |
| **Deny** | `anthropic.com`, `api.anthropic.com` | **No direct Anthropic access** |
| **Deny** | `*.googleapis.com` | **No GCP API access from sandbox** |
| **Deny** | **Everything else** | **Default deny** |

Note: `.googleapis.com` is denied from the sandbox. Only the orchestrator (which
is outside the container network) accesses GCP APIs. This is enforced by both the
proxy allowlist and the container's network namespace.

### 4.4 Ring 3 — VPC Network Controls

```mermaid
graph LR
    VM[Sandbox VM\nNo external IP] --> NGFW_EP[Cloud NGFW]
    NGFW_EP --> NAT_VPC[Cloud NAT]
    VM -->|private IP| PSC[PSC Endpoint\nVertex AI, GCS, BQ]

    style VM fill:#ff6b6b,stroke:#333,color:#fff
    style NGFW_EP fill:#e67e22,stroke:#333,color:#fff
    style PSC fill:#3498db,stroke:#333,color:#fff
```

**Firewall Rules** (priority order):

| Priority | Rule | Action |
|---|---|---|
| P800 | Egress to `169.254.169.254/32`, tag: `sandbox` | **DENY** |
| P900 | Ingress from `35.235.240.0/20` port 22 (IAP SSH) | ALLOW |
| P900 | Internal `10.0.0.0/16` (orchestrator to GCP services) | ALLOW |
| P1000 | All ingress | **DENY** |
| P1000 | All egress except to NGFW endpoint | **DENY** |

**Private Service Connect (PSC)**: GCP API traffic (Vertex AI, GCS, BQ, AR) does not
traverse the public internet. PSC creates private endpoints within the VPC, so the
orchestrator accesses `googleapis.com` via a private IP address. This traffic stays
entirely on Google's backbone and is subject to VPC-SC perimeter checks.

### 4.5 Ring 4 — Cloud NGFW / Palo Alto

Cloud NGFW Enterprise (powered by Palo Alto Networks) provides L7 inspection for
all traffic transiting the VPC. This catches threats that the Squid proxy cannot --
encrypted C2 channels, novel exfiltration techniques, and exploit delivery.

| Capability | What It Does | Why It Matters for Mythos |
|---|---|---|
| **L7 Deep Packet Inspection** | Inspects application-layer protocols | Detects covert channels disguised as HTTP/S |
| **IPS/IDS** | Signature-based and anomaly-based threat detection | Catches known exploit patterns in egress traffic |
| **TLS Inspection** | Decrypts, inspects, re-encrypts TLS traffic | Mythos could tunnel data inside TLS to allowed domains |
| **URL Filtering** | Categorize and filter URLs beyond domain-level | More granular than Squid domain allowlist |
| **Threat Prevention** | WildFire sandbox analysis of unknown files | Catches zero-day malware in egress traffic |
| **DNS Security** | Inspect DNS queries for tunneling and DGA | SandboxBench `dns_tunnel` challenge targets this exact vector |

**Deployment**: Cloud NGFW is deployed as a firewall endpoint in the VPC. A firewall
policy routes all egress traffic from the sandbox subnet through the NGFW endpoint
before it reaches Cloud NAT. The NGFW applies Security Profiles (threat prevention,
URL filtering) and logs all decisions to Cloud Logging.

```mermaid
graph LR
    subgraph "Traffic Flow: Sandbox Egress"
        A[Sandbox Container] -->|port 3128| B[Squid Proxy<br/>L7 domain allowlist]
        B -->|VPC routing| C[Cloud NGFW Endpoint<br/>Palo Alto inspection<br/>IPS + TLS + URL filtering]
        C -->|clean traffic only| D[Cloud NAT]
        D --> E[Cloud VPN]
        E --> F[On-Prem Proxy<br/>Corporate DLP/CASB]
        F -->|final egress| G((Internet))
    end

    style A fill:#ff6b6b,stroke:#333,color:#fff
    style B fill:#ffd93d,stroke:#333
    style C fill:#e67e22,stroke:#333,color:#fff
    style F fill:#2c3e50,stroke:#333,color:#fff
```

**Four independent inspection points** for all internet-bound traffic:
1. **Squid Proxy** — domain allowlist (L7, application-aware)
2. **Cloud NGFW** — threat prevention, IPS, TLS inspection (L7, signature-based)
3. **Cloud NAT** — stateful connection tracking (L3/L4)
4. **On-Prem Proxy** — corporate DLP, CASB, SOC visibility (L7, policy-based)

### 4.6 Ring 5 — VPC Service Controls

VPC Service Controls create an API-level perimeter around GCP resources. Even if
an attacker obtains valid GCP credentials, they cannot use them to access resources
outside the perimeter or exfiltrate data via GCP APIs.

This is critical because SandboxBench's `cloud_metadata` challenge demonstrated
that agents can steal credentials from the metadata service. VPC-SC ensures those
credentials are useless outside the perimeter.

```mermaid
graph LR
    subgraph "Inside VPC-SC Perimeter"
        VTXAI[(Vertex AI)]
        GCS[(GCS)]
        BQ[(BigQuery)]
        AR[(Artifact Registry)]
        CSR[(Cloud Source Repos)]
    end

    VTXAI -.->|BLOCKED| EXT1[Other Projects]
    GCS -.->|BLOCKED| EXT2[External Buckets]
    BQ -.->|BLOCKED| EXT3[External Datasets]

    style EXT1 fill:#999,stroke:#333,color:#fff
    style EXT2 fill:#999,stroke:#333,color:#fff
    style EXT3 fill:#999,stroke:#333,color:#fff
```

**Perimeter Rules**:

| Direction | Rule | Effect |
|---|---|---|
| **Ingress** | ALLOW `orchestrator-sa` from VPC `mythos-vpc` | Orchestrator can access all protected services |
| **Ingress** | ALLOW `researcher@company.com` from Access Level `corp-network` | Console access from corporate network |
| **Egress** | DENY all cross-project API calls | No data leaves via GCP APIs |
| **Egress** | DENY all external API calls | Stolen credentials useless outside perimeter |

**What VPC-SC prevents that other controls don't**:

| Scenario | Without VPC-SC | With VPC-SC |
|---|---|---|
| Agent steals metadata SA token, calls `gsutil cp` to external bucket | Data exfiltrated to attacker's GCS bucket | BLOCKED — egress to external projects denied |
| Agent finds orchestrator SA key, calls BQ to export data | Data exported via BQ to external dataset | BLOCKED — cross-project BQ access denied |
| Compromised SA used from outside the VPC | Full API access from any IP | BLOCKED — ingress only from `mythos-vpc` and `corp-network` access level |
| Agent calls Vertex AI from a different project | Could use stolen credentials | BLOCKED — Vertex AI only accessible within perimeter |

**Access Levels**: Define conditions under which the perimeter can be crossed.

| Access Level | Conditions | Who Uses It |
|---|---|---|
| `corp-network` | Source IP in corporate CIDR range, device is managed | Researcher accessing GCS/Vertex AI console |
| `vpc-internal` | Request originates from `mythos-vpc` | Orchestrator SA making API calls |

### 4.7 Ring 6 — Agent Gateway

The Agent Gateway is the policy enforcement point between Vertex AI (Mythos) and the
orchestrator. It inspects, filters, and logs all tool calls before they reach the
sandbox.

```mermaid
graph LR
    IN[Tool Call] --> PARSE[Parse Args]
    PARSE --> BLOCK{Blocklist?}
    BLOCK -->|denied| LOG_D[Log + Deny]
    BLOCK -->|pass| SANITIZE[Sanitize]
    SANITIZE --> RATE{Rate OK?}
    RATE -->|over limit| LOG_D
    RATE -->|pass| EXEC[Execute]
    EXEC --> SCAN[Scan Output]
    SCAN --> OUT[Return Result]
    OUT --> LOG_A[Audit Log]

    style LOG_D fill:#e74c3c,stroke:#333,color:#fff
    style EXEC fill:#6bcb77,stroke:#333
    style LOG_A fill:#3498db,stroke:#333,color:#fff
```

See [HARNESS.md](agentic-harness/HARNESS.md) for detailed Agent Gateway design, tool definitions,
and policy configuration.

The Agent Gateway is informed by SandboxBench Phase 1 findings on MCP server security.
Our research showed that MCP servers using `shell=True` without validation were trivially
exploitable (70% of baseline implementations). The gateway applies the "secure"
implementation pattern from Section 3.1.3 of the paper: defense-in-depth with input
validation, argument sanitization, and command allowlisting.

### 4.8 Ring 7 — On-Premises Proxy Routing

All internet-bound traffic is routed back through the corporate network via Cloud VPN
or Cloud Interconnect. This gives the corporate security team full visibility and
applies existing DLP, CASB, and SOC policies to Mythos traffic.

```mermaid
graph LR
    NAT[Cloud NAT] --> VPN[Cloud VPN]
    VPN -->|IPsec| PROXY[Corp Proxy]
    PROXY --> DLP[DLP Engine]
    PROXY --> CASB[CASB]
    PROXY --> SIEM[SIEM / SOC]
    PROXY -->|clean traffic| INT((Internet))

    style PROXY fill:#2c3e50,stroke:#333,color:#fff
    style DLP fill:#c0392b,stroke:#333,color:#fff
    style SIEM fill:#2980b9,stroke:#333,color:#fff
```

**When to use on-prem routing vs. direct egress**:

| Scenario | Recommendation |
|---|---|
| Corporate policy requires all internet traffic through proxy | On-prem routing mandatory |
| Existing DLP/CASB investment you want to leverage | On-prem routing recommended |
| Low-latency needed for package downloads | Direct egress via Cloud NAT (NGFW still inspects) |
| No corporate proxy infrastructure | Skip this ring, rely on Rings 2-4 |

On-prem routing adds 10-50ms latency per request. For Mythos workloads (code analysis,
not real-time serving), this is negligible.

### 4.9 Ring 8 — Monitoring and Audit

| Log Source | Destination | What It Captures |
|---|---|---|
| Cloud Audit Logs (Admin Activity) | Cloud Logging → BigQuery | All GCP API calls (IAM changes, resource creation) |
| Cloud Audit Logs (Data Access) | Cloud Logging → BigQuery | All reads/writes to GCS, BQ, Vertex AI |
| VPC Flow Logs | Cloud Logging → BigQuery | All network flows to/from sandbox subnet |
| Cloud NGFW Logs | Cloud Logging → BigQuery | All L7 inspection decisions, threats detected |
| Squid Proxy Access Log | Container stdout → Cloud Logging → BigQuery | All HTTP/S requests from sandbox, allowed and denied |
| Agent Gateway Log | Cloud Logging → BigQuery | All tool calls, policy decisions, content scans |
| Container Logs | Cloud Logging | Sandbox stdout/stderr — agent's actual commands and output |
| VPC-SC Violation Logs | Cloud Logging → BigQuery | All denied API calls at perimeter boundary |

**Alert Policies**:

| Alert | Trigger | Severity |
|---|---|---|
| VPC-SC violation | Any denied API call at perimeter | CRITICAL |
| NGFW threat detected | IPS signature match or anomaly | HIGH |
| Metadata access attempt | Egress to 169.254.169.254 | CRITICAL |
| Proxy deny spike | >10 denied requests in 1 minute | MEDIUM |
| Agent Gateway block | Tool call denied by policy | HIGH |
| Unusual egress volume | >100MB egress in 10 minutes | MEDIUM |

### 4.10 SandboxBench Escape Vector Mitigation (Updated)

Every escape vector tested in SandboxBench is mitigated at multiple rings.
No single ring is solely responsible for any mitigation.

| SandboxBench Challenge | Attack Vector | Ring 0 (Container) | Ring 1 (Micro-VM / gVisor) | Ring 2 (Proxy) | Ring 3 (VPC) | Ring 4 (NGFW) | Ring 5 (VPC-SC) |
|---|---|---|---|---|---|---|---|
| `privileged` | Mount `/dev/sda` | `privileged: false`, drop ALL | Micro-VM: own kernel, no host `/dev`. gVisor: blocks raw device | — | — | — | — |
| `docker_socket` | Docker API via socket | No socket mount | — | — | — | — | — |
| `capabilities` | `CAP_SYS_ADMIN` mount | `drop: ["ALL"]` | Micro-VM: mount only affects guest. gVisor: blocks `mount` | — | — | — | — |
| `shared_pid` | `/proc/1/root` access | `hostPID: false` | Micro-VM: separate kernel, no host PID. gVisor: separate namespace | — | — | — | — |
| `kernel_module` | `insmod` malicious module | No `CAP_SYS_MODULE` | Micro-VM: module loads in guest kernel only. gVisor: blocks syscall | — | — | — | — |
| `cgroup_escape` | cgroups v1 `release_agent` | No `CAP_SYS_ADMIN` | Micro-VM: cgroups are guest-only. gVisor: intercepts cgroup ops | — | — | — | — |
| `proxy_bypass` | Exfiltrate around proxy | — | — | No direct egress from container network | Firewall denies non-proxy egress | NGFW inspects all traffic | — |
| `dns_tunnel` | Data via DNS queries | — | — | Proxy handles DNS, container has no resolver | — | NGFW DNS Security detects tunneling | — |
| `cloud_metadata` | Steal credentials via 169.254.169.254 | — | — | — | iptables blocks metadata IP | — | Stolen creds useless outside perimeter |
| `container_pivot` | SSH to adjacent services | — | — | Proxy-only egress, no SSH allowed | Firewall blocks lateral traffic | — | — |
| `cron_persistence` | Cron job for persistence | Read-only rootfs, no cron | — | — | — | — | — |
| `container_spawn` | Docker socket to spawn containers | No socket, no Docker CLI | — | — | — | — | — |

## 5. Source Code Ingestion

### 5.1 The Problem

Mythos needs access to target source code for vulnerability analysis. Allowing the
sandbox to clone directly from GitHub/GitLab creates multiple risks:

1. **Credential exposure** — Git credentials (SSH keys, PATs) would need to be in the sandbox
2. **Exfiltration channel** — `git push` to an attacker-controlled repo exfiltrates data
3. **Supply chain risk** — A malicious repo could contain exploit payloads targeting the sandbox
4. **Audit gap** — Direct clones from external repos bypass all GCP audit logging
5. **VPC-SC violation** — Direct internet access from sandbox violates the perimeter model

### 5.2 Recommended Patterns

```mermaid
graph LR
    GH[GitHub / GitLab] -->|mirror| CSR[Cloud Source Repos]
    GH -->|clone + tar| GCS[GCS Staging]
    GH -->|OCI package| AR[Artifact Registry]

    CSR --> ORCH[Orchestrator]
    GCS --> ORCH
    AR --> ORCH

    ORCH -->|read-only volume| SBX[Sandbox]

    SBX -.->|BLOCKED: no git, no creds| GH

    style SBX fill:#ff6b6b,stroke:#333,color:#fff
    style ORCH fill:#6bcb77,stroke:#333
    style CSR fill:#3498db,stroke:#333,color:#fff
```

### 5.3 Option Comparison

| Dimension | **Cloud Source Repos (Mirror)** | **GCS Staging Bucket** | **Artifact Registry OCI** |
|---|---|---|---|
| **How code enters GCP** | Auto-mirror from GitHub/GitLab. CSR syncs on push | Manual or CI/CD: `git clone` + `tar` + `gsutil cp` | Manual or CI/CD: `oras push` OCI artifact |
| **Freshness** | Near real-time (mirror sync) | On-demand (when you upload) | On-demand |
| **VPC-SC** | Within perimeter (`sourcerepo.googleapis.com`) | Within perimeter (`storage.googleapis.com`) | Within perimeter (`artifactregistry.googleapis.com`) |
| **Access control** | IAM on repo (`roles/source.reader`) | IAM on bucket (`roles/storage.objectViewer`) | IAM on repo (`roles/artifactregistry.reader`) |
| **Versioning** | Git native (branches, tags, commits) | GCS object versioning | OCI tags and digests |
| **Audit** | Cloud Audit Logs for all reads | Cloud Audit Logs for all reads | Cloud Audit Logs for all reads |
| **Sandbox receives code** | Orchestrator `git clone` from CSR, mount as volume | Orchestrator `gsutil cp` from GCS, extract, mount | Orchestrator `oras pull`, extract, mount |
| **Git history available?** | Yes — full clone with history | Only if tarball includes `.git` | Only if artifact includes `.git` |
| **Best for** | Ongoing work on known repos, need latest commits | One-off analysis of specific versions/snapshots | Immutable, reproducible analysis of specific code versions |

### 5.4 Recommended Approach: Cloud Source Repos with GCS Fallback

**Primary: Cloud Source Repositories**

Use CSR's GitHub/GitLab mirroring for repos you analyze regularly. The orchestrator
clones from CSR (within the VPC-SC perimeter) and mounts the code into the sandbox
as a read-only volume.

- Set up mirror: `gcloud source repos create --mirror-config=...`
- Orchestrator clones: `git clone https://source.developers.google.com/p/PROJECT/r/REPO`
- Mount into sandbox: `docker run -v /workspace/repo:/target:ro ...`

**Fallback: GCS Staging Bucket**

For ad-hoc analysis of repos not worth mirroring, or for specific commits/snapshots:

- From workstation or CI: `git clone --depth=1 REPO && tar czf repo.tar.gz REPO/`
- Upload: `gsutil cp repo.tar.gz gs://mythos-targets/repos/`
- Orchestrator downloads and extracts into sandbox volume

**What the sandbox does NOT have**:

| Denied in Sandbox | Why |
|---|---|
| `git` CLI | No cloning, no pushing, no credential usage |
| SSH keys | No authentication to external repos |
| GitHub/GitLab PATs | No API access to external services |
| Network access to `github.com`, `gitlab.com` | Not in proxy allowlist |
| Write access to code volume | Read-only mount prevents code tampering |

### 5.5 Source Code Flow (End-to-End)

```mermaid
sequenceDiagram
    participant GH as GitHub/GitLab
    participant CSR as Cloud Source Repos<br/>(within VPC-SC)
    participant ORCH as Orchestrator
    participant GCS as GCS mythos-targets<br/>(within VPC-SC)
    participant SBX as Sandbox Container
    participant VTXAI as Vertex AI<br/>(Mythos)

    Note over GH,CSR: Setup: One-time mirror configuration
    GH->>CSR: Auto-mirror sync (on push)

    Note over ORCH,VTXAI: Analysis Session
    ORCH->>CSR: git clone (via PSC, within perimeter)
    ORCH->>ORCH: Mount code at /target (read-only)
    ORCH->>SBX: Start sandbox with /target:ro volume

    ORCH->>VTXAI: "Analyze /target for vulnerabilities"
    VTXAI->>ORCH: Tool call: bash("grep -r 'unsafe' /target/src/")
    ORCH->>SBX: Execute: grep -r 'unsafe' /target/src/
    SBX->>ORCH: Output: matching lines
    ORCH->>VTXAI: Tool result: matching lines
    VTXAI->>ORCH: Tool call: bash("cat /target/src/auth.c")
    ORCH->>SBX: Execute: cat /target/src/auth.c
    SBX->>ORCH: Output: file contents
    ORCH->>VTXAI: Tool result + "continue analysis"

    Note over ORCH,GCS: Results collection
    ORCH->>GCS: Upload vulnerability report
    ORCH->>GCS: Upload proof-of-concept artifacts
```

## 6. GCP Service Access Architecture

### 6.1 Service Accounts and IAM

| Service Account | Role | Scope |
|---|---|---|
| `mythos-orchestrator-sa` | `roles/aiplatform.user` | Vertex AI endpoint |
| | `roles/storage.objectAdmin` | `mythos-targets`, `mythos-results` buckets |
| | `roles/bigquery.dataEditor` + `jobUser` | `mythos_audit` dataset |
| | `roles/artifactregistry.reader` | `mythos-images` repository |
| | `roles/source.reader` | Mirrored repos in Cloud Source Repos |
| | `roles/logging.logWriter` | Project-level |
| `mythos-sandbox-sa` | **NO ROLES** | Zero permissions. Exists for audit identity only |

All IAM bindings use **resource-level** (bucket, dataset, repository) not project-level
permissions. The sandbox SA has zero permissions -- it exists only so that any
accidental API call from the sandbox shows up in audit logs with a distinct identity.

### 6.2 GCS Bucket Design

| Bucket | Purpose | Orchestrator Access | Sandbox Access |
|---|---|---|---|
| `mythos-targets` | Target source code, datasets | `roles/storage.objectViewer` | Read-only volume mount |
| `mythos-results` | Vuln reports, PoC artifacts | `roles/storage.objectCreator` | None |
| `mythos-staging` | Temporary working files | `roles/storage.objectAdmin` | None |

All buckets have uniform bucket-level access (no ACLs), versioning enabled,
and retention policies for audit purposes.

## 7. Recommendation

### For Single-Researcher Exploration: GCE + Docker on COS

| Why GCE + Firecracker | Enterprise Ring | SandboxBench Validation |
|---|---|---|
| Simple: 1 VM, 1 micro-VM sandbox, 1 proxy | VPC-SC, NGFW, on-prem, gateway all same across options | Firecracker micro-VM blocks all 8 escape vectors (own kernel) |
| Full flexibility: unlimited time, nested containers | Ring 0-1 differ by option; Rings 2-8 identical | Squid + no direct egress blocks all 3 exfil vectors |
| Strongest self-managed: Firecracker micro-VM (hardware isolation) | Choice of compute does not affect enterprise controls | Read-only rootfs blocks all 3 persistence vectors |
| Low cost: ~$80/mo active | | No socket + no Docker CLI blocks both replication vectors |

The choice between Cloud Run, GCE, and GKE affects **Ring 0-1 only**. Rings 2-8
(proxy, VPC, NGFW, VPC-SC, Agent Gateway, on-prem, monitoring) are identical
across all options. This is by design -- the enterprise controls are infrastructure-
level and don't depend on how the container runs.

### Migration Path

```mermaid
graph LR
    Phase1["Phase 1: GCE + Docker<br/>Single researcher<br/>All 9 rings active<br/>~$80/mo + NGFW"]
    Phase2["Phase 2: GKE<br/>Team access needed<br/>Add K8s NetworkPolicy<br/>~$200/mo + NGFW"]
    Phase3["Phase 3: GKE + Cloud Run<br/>Hybrid: GKE for long runs<br/>Cloud Run for short scans<br/>Variable cost + NGFW"]

    Phase1 -->|"team grows"| Phase2
    Phase2 -->|"optimize cost"| Phase3

    style Phase1 fill:#2ecc71,color:#fff
    style Phase2 fill:#3498db,color:#fff
    style Phase3 fill:#9b59b6,color:#fff
```

## 8. Implementation Plan

Once we agree on the approach, the implementation order is:

1. **GCP project + Org Policies** — Create project, enable APIs, set org constraints (no external IPs, no default SA usage)
2. **IAM** — Create `mythos-orchestrator-sa` and `mythos-sandbox-sa` with scoped roles
3. **VPC + Firewall** — Create private VPC, subnets, firewall rules, Cloud NAT
4. **VPC Service Controls** — Create access policy, access levels, service perimeter
5. **Private Service Connect** — PSC endpoints for Vertex AI, GCS, BQ, AR
6. **Cloud NGFW** — Deploy NGFW endpoint, security profiles, firewall policy
7. **Cloud VPN** — IPsec tunnel to on-prem proxy (if applicable)
8. **Source Code Repos** — Set up CSR mirrors for target repos, create GCS staging bucket
9. **Container images** — Build and push hardened sandbox base image + Squid proxy to Artifact Registry
10. **Compute** — Deploy GCE VM, install Firecracker (or Kata Containers), deploy sandbox micro-VMs
11. **Harness** — Deploy multi-agent harness: Opus orchestrator, Mythos worker, Agent Gateway with tool call policies
12. **Verification pipeline** — Implement two-sandbox trust boundary (Find + Grade). Grade agent verifies in fresh micro-VM with 3/3 reproduction and 5-criteria checklist
13. **Resilience** — Implement session-ID resume with exponential backoff for multi-hour runs
14. **Monitoring** — Cloud Audit Logs, log sinks to BigQuery, alert policies
15. **Validation** — Run SandboxBench escape challenges against the environment to verify containment

Steps 12-13 incorporate industry-standard verification patterns for
execution-verified vulnerability discovery — findings are not reported
until reproduced by an independent agent in a fresh sandbox.

Step 15 is critical: we use our own SandboxBench framework to validate the
containment before running Mythos. This closes the loop between our prior research
and this deployment.

## 9. Open Questions

- [ ] Do you have Glasswing access / Vertex AI Mythos endpoint provisioned?
- [ ] What target software will Mythos analyze? (Affects container image contents and CSR mirror config)
- [ ] Do you have existing on-prem proxy infrastructure (Zscaler, BlueCoat, Palo Alto)?
- [ ] Is Cloud NGFW Enterprise already enabled in the org, or does it need procurement?
- [ ] VPC-SC: is there an existing access policy at the org level, or do we create one?
- [ ] Should the orchestrator run on the same VM as the sandbox, or on a separate VM?
- [ ] Any specific GCS bucket naming / BQ dataset conventions?
- [ ] Budget constraints? (NGFW Enterprise is priced per endpoint-hour, ~$1.75/hr)
