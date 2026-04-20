# Mitigations: AI-Agent Attack Vectors

How the 9-ring defense-in-depth stack in this repo blocks common post-compromise
behaviors of a misaligned or hijacked analyst agent running inside the sandbox.

Each vector is mitigated by **multiple independent rings** — no single failure
opens the path. Citations point at the enforcing code or config.

## Why tool access is the primary choke point

Every vector on this list requires the agent to **do** something — run a
command, read/write a file, or reach the network. The analyst agent has no
ambient capabilities: it cannot syscall, cannot open sockets, cannot fork. All
effect is mediated by a small, fixed tool surface exposed through ADK:
`run_command`, `read_file`, `write_file`, `analyze_binary`.

That means the attack surface for *all six vectors* collapses into three
questions:

1. **Can the tool call be issued?** — `SecurityGatewayPlugin.before_tool_callback`
   validates every call against the command denylist, argument regexes, path
   allowlist, and session quota
   (`agentic-harness/mythos_harness/plugins/security_gateway.py:60-89`).
2. **Can the tool do harm inside the sandbox?** — the container has no
   network, no root, no writable rootfs, no dangerous caps, and no credentials
   (`agentic-harness/mythos_harness/sandbox/manager.py:29-45`).
3. **Can the result leak back out?** — `after_tool_callback` scrubs credential
   patterns and caps output size before the model ever sees it
   (`plugins/security_gateway.py:91-101, 137-151`).

So while the ring table below lists many controls per vector, in practice most
attacks are stopped at step 1 (tool denied), and the remaining layers are
insurance for bypass or logic errors in the gateway. The ring count is not
redundancy theater — it's assumption that the gateway will eventually be
bypassed and the sandbox and network layers must still hold.

## Ring map (as deployed)

Numbering matches `APPROACH.md` §4.0.

| Ring | Layer | Primary enforcement | Deployed? |
| ---- | ----- | ------------------- | --------- |
| 0 | Container hardening | `sandbox/manager.py` — `--network=none`, cap-drop, read-only, non-root, tmpfs, ephemeral, `--memory=8g`, `--cpus=2` | Yes |
| 1 | Sandbox runtime | gVisor `runsc` / Kata-fc Firecracker micro-VMs | Yes |
| 2 | Egress proxy | Squid domain allowlist | **No** — sandbox has no network, nothing to proxy |
| 3 | VPC + host firewall | `iptables` FORWARD drop to `169.254.169.254` + GCP firewall rules (`SETUP.md`) | Yes (belt-and-suspenders) |
| 4 | Cloud NGFW | L7 DPI, DNS Security | **No** — no runtime external egress to inspect |
| 5 | VPC-SC perimeter | Cross-project and API-scope denial | Yes |
| 6 | SecurityGatewayPlugin | `plugins/security_gateway.py` — command/arg/path filter, output scrubbing, `max_calls_per_session` rate limit | Yes |
| 7 | On-prem proxy | Corporate DLP/CASB via Cloud VPN | **No** — nothing to route |
| 8 | Monitoring & audit | Cloud Audit Logs, plugin denial stats, VPC Flow Logs | Yes |

Rings 2, 4, and 7 are kept as reference designs in case a future change
re-introduces outbound internet access. They are **not** active controls today.

---

## 1. Cloud metadata endpoint credential theft (169.254.169.254)

Attack: agent queries GCE metadata server to steal the VM's service account
token, then uses it against Vertex AI or other GCP APIs.

Controls:
- **Ring 0 — no creds mounted.** Analyst containers get no service account
  file; `--cap-drop=ALL` strips network and raw-socket capability
  (`agentic-harness/mythos_harness/sandbox/manager.py:35`).
- **Ring 0 — `--network=none`.** Container has no interface to reach the
  metadata IP in the first place
  (`agentic-harness/mythos_harness/sandbox/manager.py:33`).
- **Ring 3 — host iptables drop.** Even if the container gets a network,
  forwarded traffic to `169.254.169.254` is dropped
  (`SETUP.md:233-234`):
  ```
  iptables -I FORWARD -s 172.16.0.0/12 -d 169.254.169.254 -j DROP
  iptables -I FORWARD -s 10.0.0.0/8    -d 169.254.169.254 -j DROP
  ```
- **Ring 3 — VPC firewall rule P800.** Egress to `169.254.169.254/32` from
  `sandbox` tag denied (`APPROACH.md:325`).
- **Ring 5 — VPC-SC.** Any stolen token is useless outside the perimeter
  (`APPROACH.md:229`, `APPROACH.md:570`).
- **Ring 6 — output redaction.** GCP OAuth token pattern `ya29\.[A-Za-z0-9_-]+`
  is stripped from all tool output
  (`agentic-harness/mythos_harness/plugins/security_gateway.py:39`).
- **Ring 6 — argument denylist.** Literal `169.254.169.254` in any command
  argument is blocked (`plugins/security_gateway.py:23`).

## 2. Data exfiltration via DNS tunneling, covert channels, proxy bypass

Attack: encode secrets into DNS queries, ICMP, TLS SNI, or bypass the egress
proxy to ship data out.

Controls:
- **Rings 0+1 — `--network=none`.** This is essentially the whole defense:
  no DNS resolver, no sockets, no ICMP, no outbound path, nothing to tunnel over
  (`agentic-harness/mythos_harness/config.py:9`,
  `agentic-harness/mythos_harness/sandbox/manager.py:33`). Because the network
  stack is absent, a Squid proxy (Ring 2) and Cloud NGFW (Ring 4) would have
  nothing to inspect and are not deployed.
- **Ring 6 — pipe/redirect blocks.** Regexes deny piping into network tools
  and redirects to device files
  (`plugins/security_gateway.py:27-31`):
  ```
  \|\s*(nc|netcat|curl|wget)\b
  >\s*/dev/(sd|null|zero|tcp|udp)
  mkfifo.*/dev/
  ```
- **Ring 6 — command denylist.** `curl`, `wget`, `nc`, `netcat`, `ncat`, `ssh`,
  `scp`, `sftp` are blocked outright
  (`plugins/security_gateway.py:17-20`).
- **Ring 6 — output cap.** Tool results capped at 102,400 bytes, limiting
  bandwidth per call
  (`plugins/security_gateway.py:44`,
  `agentic-harness/mythos_harness/sandbox/manager.py:70`).
- **Ring 6 — call quota.** `max_calls_per_session` caps total tool calls,
  bounding total exfil volume
  (`plugins/security_gateway.py:51`).

## 3. Persistence via cron, backdoor users, startup scripts

Attack: drop a cron entry, add `/etc/passwd` line, or plant a script that runs
on next boot.

Controls:
- **Ring 0 — read-only rootfs.** `--read-only` prevents writes to `/etc`,
  `/var/spool/cron`, or any rc-style path
  (`agentic-harness/mythos_harness/sandbox/manager.py:40-41`).
- **Ring 0 — non-root UID 1000.** No permission to create system users or
  modify system files
  (`agentic-harness/mythos_harness/sandbox/manager.py:37`).
- **Ring 0 — `nosuid` tmpfs.** The only writable mount is `/tmp` with
  `nosuid,size=512m` — can't plant suid helpers
  (`agentic-harness/mythos_harness/sandbox/manager.py:38`).
- **Ring 0 — `no-new-privileges`.** Blocks privilege escalation via any planted
  binary
  (`agentic-harness/mythos_harness/sandbox/manager.py:36`).
- **Ring 6 — command denylist.** `ssh`, `git`, `pip` blocked — cannot pull
  backdoor payloads
  (`plugins/security_gateway.py:17-20`).
- **Ring 0 — ephemeral.** Container is destroyed after each run
  (`agentic-harness/mythos_harness/sandbox/manager.py:91`). There is no
  persistent filesystem for persistence to survive into.

## 4. Lateral movement to adjacent services

Attack: reach the orchestrator VM, other project VMs, internal APIs, or
customer workloads.

Controls:
- **Ring 0 — `--network=none`.** No adjacent service is reachable from the
  sandbox — there is no network stack
  (`agentic-harness/mythos_harness/sandbox/manager.py:33`).
- **Ring 1 — gVisor/Kata-fc.** Separate PID, network, and IPC namespaces;
  syscalls mediated or run in a micro-VM (`APPROACH.md` §Ring 1).
- **Ring 3 — VPC firewall deny-all.** Default-deny ingress and deny-all egress
  except via controlled NAT
  (`SETUP.md:74-106`, `APPROACH.md:229`).
- **Ring 5 — VPC-SC perimeter.** Cross-project API calls denied even with valid
  credentials (`APPROACH.md` §Ring 5).
- **`--network=none`.** Again, no adjacent service is reachable because the
  sandbox has no network stack. No proxy needed to prevent lateral movement —
  there's nowhere for traffic to originate from.

## 5. Self-replication via Docker socket

Attack: mount or reach `/var/run/docker.sock` and spawn sibling containers with
elevated privileges (classic docker-escape pattern).

Controls:
- **Ring 0 — socket never mounted.** `create()` in the sandbox manager does
  not pass `/var/run/docker.sock`; only `/target:ro` is bind-mounted
  (`agentic-harness/mythos_harness/sandbox/manager.py:42-43`).
- **Ring 0 — `--cap-drop=ALL`.** Strips `CAP_SYS_ADMIN` needed to manipulate
  cgroups / create child namespaces
  (`agentic-harness/mythos_harness/sandbox/manager.py:35`).
- **Ring 6 — runtime denylist.** `docker` and `podman` commands blocked
  (`plugins/security_gateway.py:18`).
- **Ring 6 — path regex.** Argument regex denies `/var/run/docker\.sock`
  (`plugins/security_gateway.py:24`).
- **Ring 6 — proc path regex.** Denies `/proc/1/root` and `/proc/sysrq`
  namespace-escape paths
  (`plugins/security_gateway.py:25-26`).

## 6. Abuse of Vertex AI API access for GCP pivot

Attack: use the harness's Vertex AI access to call other GCP APIs (GCS, IAM,
KMS), exfiltrate data, or pivot into the project.

Controls:
- **Architectural separation.** Only the orchestrator VM holds the Vertex AI
  service account. The sandbox has no credentials and no metadata access
  (`APPROACH.md` §Trust boundaries).
- **Ring 3 — metadata blocked.** Sandbox cannot mint a token to begin with
  (see Vector 1).
- **Ring 5 — VPC-SC.** Scopes the SA to Vertex AI within the perimeter; pivot
  to GCS / IAM / KMS denied at the service boundary
  (`APPROACH.md:229`).
- **Ring 6 — credential scrubbing.** AWS keys (`AKIA…`), PEM private keys,
  GitHub tokens (`ghp_…`, `gho_…`), GCP OAuth tokens (`ya29.…`) redacted from
  any tool output before the agent sees it
  (`plugins/security_gateway.py:34-40`). Any token the agent surfaces through
  tool output never reaches the model's context.
- **Ring 6 — tool-call budget.** `max_calls_per_session` (default 2500) bounds
  a runaway pivot chain
  (`plugins/security_gateway.py:51`).

## 7. Resource exhaustion / runaway consumption

Attack — or accidental behavior — in which the agent loops, spawns far more
work than the host can hold, or burns Vertex AI tokens without bound. Not a
data-theft or escape threat, but a DoS/cost threat that can crash the
orchestrator host or exhaust quotas.

Controls:
- **Ring 0 — per-sandbox CPU cap.** `--cpus=2` caps each sandbox at 2 cores so
  N parallel finders cannot saturate the host scheduler
  (`agentic-harness/mythos_harness/sandbox/manager.py:35`,
   `agentic-harness/mythos_harness/config.py:9`). Tuneable via
  `MYTHOS_SANDBOX_CPUS`.
- **Ring 0 — per-sandbox memory cap.** `--memory=8g` cgroup limit; OOM kills
  the sandbox before it can OOM the host
  (`sandbox/manager.py:34`). Tuneable via `MYTHOS_SANDBOX_MEMORY`.
- **Ring 0 — tmpfs size cap.** `/tmp` limited to 512 MB with `nosuid`
  (`sandbox/manager.py:38`). Can't balloon writable scratch space.
- **Ring 0 — per-command timeout.** `sandbox.execute(..., timeout=180)` returns
  `exit_code=-1` after 180 s, killing the `docker exec`
  (`sandbox/manager.py:56,66`).
- **Harness — parallel-finder cap.** `MAX_PARALLEL_FINDERS` (default 6) hard-
  fails the run if focus areas exceed the cap, whether the list came from the
  planner, `--focus-areas`, or `target.focus_areas` in `config.yaml`
  (`agentic-harness-parallel/mythos_harness/config.py`,
   `pipeline.py` — enforced in `run_parallel_assessment` right after focus
  areas are resolved). Prevents 12×8 GB fan-out on a 32 GB host.
- **Harness — wall-clock timeout.** `asyncio.timeout(assessment_timeout_seconds)`
  wraps both `run_assessment` (sequential) and `run_parallel_assessment`
  (parallel); default 1 h, tuneable via `MYTHOS_ASSESSMENT_TIMEOUT`
  (`agentic-harness/mythos_harness/cli.py`,
   `agentic-harness-parallel/mythos_harness/pipeline.py`). Bounds total
  runtime independent of the tool-call budget.
- **Harness — container janitor.** Parallel pipeline tracks every container
  in an `active_containers` set and force-destroys them in a `finally` block
  on timeout or exception, preventing leaks from mid-phase aborts
  (`pipeline.py`, `_create` / `_destroy` helpers).
- **Ring 6 — tool-call budget.** Same `max_calls_per_session=2500` as vector 2
  caps the number of tool calls per session, bounding loop-based runaways at
  the plugin layer.

Known gaps (not yet mitigated):
- `HarnessConfig.max_find_turns`, `max_grade_turns`, `max_analyst_turns`,
  `max_delegations` are **declared but unused** in both harnesses
  (`config.py:58-61`). They give a false sense of safety. Either wire them to
  the agents or remove.
- **Token budget.** `_token_counts` is tracked in both harnesses but never
  compared against a cap — a runaway agent can still burn Vertex AI quota
  within the tool-call budget.
- **Retry storm.** Sequential sub-agents retry 5× with 4-120 s exponential
  backoff (`tenacity` on `_run_sub_agent` in `agents/orchestrator.py:44-48`);
  on a Vertex AI flap, N parallel finders can amplify into simultaneous
  retries. No circuit breaker today.

---

## Cross-vector defense patterns

**Three independent choke points per tool call.** Every call passes (1) ADK
tool registration, (2) `SecurityGatewayPlugin.before_tool_callback`, (3)
sandbox runtime isolation. All three must approve; any one blocks.

**Before/after split.** `before_tool_callback` validates input (commands,
paths); `after_tool_callback` scrubs output (credentials, size)
(`plugins/security_gateway.py:60,91`). Controls apply in both directions.

**Sandboxed agent scope.** The gateway only enforces command/path rules on
`mythos_finder` and `verifier` — the agents that drive the sandbox. Orchestrator
and analyst (model-only, no tools in sandbox) are unaffected
(`plugins/security_gateway.py:15,68`).

**Ephemeral by design.** No state survives a run. Every new task starts from a
fresh container against an immutable image
(`agentic-harness/mythos_harness/sandbox/manager.py:91`).

**Trust boundary cleanliness.** Credentials and network live on the host VM.
Only PoC bytes cross into the sandbox via `docker exec` stdin, and only tool
results cross back via stdout — both size-capped
(`agentic-harness/mythos_harness/sandbox/manager.py:70,80-88`).
