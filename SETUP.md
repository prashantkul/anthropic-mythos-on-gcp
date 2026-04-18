# GCE VM Setup for Mythos Harness

[Back to README](README.md) | [Architecture](APPROACH.md) | [Harness Design](agentic-harness/HARNESS-DESIGN.md)

## Prerequisites

- GCP project with billing enabled
- `gcloud` CLI authenticated (`gcloud auth login`)
- Owner or Editor role on the project

## 1. Enable APIs

```bash
gcloud services enable \
  compute.googleapis.com \
  aiplatform.googleapis.com \
  storage.googleapis.com \
  bigquery.googleapis.com \
  artifactregistry.googleapis.com \
  logging.googleapis.com \
  iap.googleapis.com \
  --project=YOUR_PROJECT_ID
```

Note: Cloud Source Repositories may not be available on all projects. Skip if
you get a permission error — use GCS staging for code ingestion instead.

## 2. Service Accounts

Two service accounts with strict separation:

```bash
PROJECT=YOUR_PROJECT_ID

# Orchestrator SA — has GCP credentials for Vertex AI, GCS, logging
gcloud iam service-accounts create mythos-orchestrator-sa \
  --display-name="Mythos Harness Orchestrator" \
  --project=$PROJECT

# Sandbox SA — zero permissions, exists for audit identity only
gcloud iam service-accounts create mythos-sandbox-sa \
  --display-name="Mythos Sandbox (no permissions)" \
  --project=$PROJECT

# Grant scoped roles to orchestrator
SA=mythos-orchestrator-sa@${PROJECT}.iam.gserviceaccount.com
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" --role="roles/aiplatform.user" --quiet
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" --role="roles/logging.logWriter" --quiet
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:$SA" --role="roles/storage.objectAdmin" --quiet
```

## 3. VPC and Networking

Private VPC with no ingress, IAP-only SSH, and Cloud NAT for egress:

```bash
# Create VPC
gcloud compute networks create mythos-vpc \
  --subnet-mode=custom \
  --project=$PROJECT

# Create subnet with Private Google Access (Vertex AI via private IP)
gcloud compute networks subnets create mythos-subnet \
  --network=mythos-vpc \
  --region=us-central1 \
  --range=10.0.1.0/24 \
  --enable-private-ip-google-access \
  --project=$PROJECT

# Firewall: deny all ingress
gcloud compute firewall-rules create mythos-deny-all-ingress \
  --network=mythos-vpc \
  --direction=INGRESS \
  --action=DENY \
  --rules=all \
  --priority=1000 \
  --source-ranges=0.0.0.0/0 \
  --project=$PROJECT

# Firewall: allow IAP SSH only
gcloud compute firewall-rules create mythos-allow-iap-ssh \
  --network=mythos-vpc \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:22 \
  --priority=900 \
  --source-ranges=35.235.240.0/20 \
  --target-tags=mythos-sandbox \
  --project=$PROJECT

# Cloud NAT for outbound (no external IP on VM)
gcloud compute routers create mythos-router \
  --network=mythos-vpc \
  --region=us-central1 \
  --project=$PROJECT

gcloud compute routers nats create mythos-nat \
  --router=mythos-router \
  --region=us-central1 \
  --auto-allocate-nat-external-ips \
  --nat-all-subnet-ip-ranges \
  --project=$PROJECT
```

## 4. Create the GCE VM

```bash
gcloud compute instances create mythos-harness \
  --zone=us-central1-a \
  --machine-type=n1-standard-8 \
  --image-family=ubuntu-2204-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB \
  --boot-disk-type=pd-ssd \
  --enable-nested-virtualization \
  --min-cpu-platform="Intel Haswell" \
  --no-address \
  --network=mythos-vpc \
  --subnet=mythos-subnet \
  --tags=mythos-sandbox \
  --service-account=mythos-orchestrator-sa@${PROJECT}.iam.gserviceaccount.com \
  --scopes=cloud-platform \
  --project=$PROJECT
```

Key flags:
- `--no-address` — no external IP, access via IAP tunnel only
- `--enable-nested-virtualization` — required for Kata/Firecracker (future)
- `--service-account` — orchestrator SA, not the default compute SA
- `--tags=mythos-sandbox` — matches the IAP SSH firewall rule

### SSH Access

```bash
gcloud compute ssh mythos-harness \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --project=$PROJECT
```

## 5. Install Docker + gVisor

On the VM:

```bash
# Docker
sudo apt-get update
sudo apt-get install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# gVisor (runsc)
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main' \
  | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update
sudo apt-get install -y runsc

# Register runsc as Docker runtime
sudo runsc install

# Configure Docker DNS — VPC has no default DNS for containers.
# Use GCP metadata DNS as primary, Google public DNS as fallback.
cat <<'DEOF' | sudo tee /etc/docker/daemon.json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/bin/runsc"
        }
    },
    "dns": ["169.254.169.254", "8.8.8.8"]
}
DEOF
sudo systemctl restart docker

# Verify gVisor works (should show kernel 4.4.0, not host kernel)
docker run --rm --runtime=runsc alpine uname -r
```

> **Note**: The DNS config is required because our private VPC has no default
> DNS for Docker containers. Without it, `docker build` fails with
> `Temporary failure resolving` errors. The metadata DNS (`169.254.169.254`)
> is accessible from Docker build containers (only blocked from runtime
> containers via iptables FORWARD rules in Step 6).

### Kata Containers (Future — Requires Nested Virtualization)

Kata Containers with Firecracker backend provides hardware-enforced isolation
(each container gets its own kernel via KVM). Currently blocked on GCE because
`kvm_intel` module doesn't load on n1/n2 instances despite
`--enable-nested-virtualization`. This is a known GCE issue.

When nested virt is available:

```bash
# Install Kata
sudo mkdir -p /etc/apt/keyrings
wget -qO- https://packages.kata-containers.io/kata-containers.gpg \
  | sudo tee /etc/apt/keyrings/kata-containers.gpg
echo "deb [signed-by=/etc/apt/keyrings/kata-containers.gpg] https://packages.kata-containers.io/stable/ubuntu/ $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/kata-containers.list
sudo apt-get update
sudo apt-get install -y kata-containers

# Register Kata as Docker runtime
cat <<'EOF' | sudo tee /etc/docker/daemon.json
{
  "runtimes": {
    "kata-fc": {
      "path": "/usr/bin/kata-runtime",
      "runtimeArgs": ["--kata-config", "/etc/kata-containers/configuration-fc.toml"]
    }
  }
}
EOF
sudo systemctl restart docker

# Verify (should show a different kernel version than host)
docker run --rm --runtime=kata-fc alpine uname -r
```

## 6. Block Metadata Service from Containers

The host VM needs metadata access for its GCP service account (Vertex AI, GCS).
Containers must NOT have metadata access. These iptables rules block metadata
for forwarded traffic (containers) while preserving it for the host:

```bash
# Block metadata from Docker container subnets only
sudo iptables -I FORWARD -s 172.16.0.0/12 -d 169.254.169.254 -j DROP
sudo iptables -I FORWARD -s 10.0.0.0/8 -d 169.254.169.254 -j DROP

# Persist across reboots
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
sudo netfilter-persistent save

# Verify host CAN reach metadata
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/hostname
# → should return hostname

# Verify container CANNOT reach metadata
docker run --rm alpine wget -qO- --timeout=3 http://169.254.169.254/ 2>&1
# → should timeout
```

## 7. Install the Harness

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.local/bin/env

# Clone and install
git clone https://github.com/prashantkul/anthropic-mythos-on-gcp.git
cd anthropic-mythos-on-gcp/agentic-harness
uv sync

# Configure environment
cp .env.example .env
# Edit .env:
#   GOOGLE_CLOUD_PROJECT=your-project-id
#   GOOGLE_CLOUD_LOCATION=us-central1
#   GOOGLE_GENAI_USE_VERTEXAI=True
#   MYTHOS_SANDBOX_RUNTIME=runsc

# Verify
uv run python -c "import mythos_harness; print('OK')"
```

## 8. Prepare a Target

Each target is a directory with a Dockerfile (ASAN-instrumented build) and
config.yaml:

```bash
mkdir -p targets/my-target
```

```yaml
# targets/my-target/config.yaml
image_tag: "mythos-my-target:latest"
source_root: "/target/src"
binary_path: "/target/bin/my-target"
focus_areas:
  - "input parsing"
  - "memory management"
```

```dockerfile
# targets/my-target/Dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y gcc libasan6
COPY src/ /target/src/
RUN gcc -fsanitize=address -g -o /target/bin/my-target /target/src/main.c
```

```bash
# Build the target image
docker build -t mythos-my-target:latest targets/my-target/
```

## 9. Run an Assessment

```bash
uv run mythos-harness targets/my-target \
  --runtime runsc \
  --finder-model claude-mythos@latest \
  --orchestrator-model claude-opus@latest
```

Results are saved to `results/my-target/`.

## Current VM State

| Component | Status | Notes |
|---|---|---|
| GCE VM (`mythos-harness`) | Running | `n1-standard-8`, `10.0.1.3`, no external IP |
| VPC (`mythos-vpc`) | Configured | Private, deny-all ingress, IAP SSH only |
| Cloud NAT (`mythos-nat`) | Configured | Egress for package installs |
| Docker | `29.1.3` | Installed and running |
| gVisor (`runsc`) | `20260413.0` | Verified (emulated kernel `4.4.0`) |
| Kata Containers | Not available | Blocked by nested virt issue on GCE |
| Metadata block | Active | iptables FORWARD rules, persisted |
| Service accounts | Configured | `mythos-orchestrator-sa` (Vertex AI + GCS), `mythos-sandbox-sa` (zero perms) |
| Harness | Installed | `uv sync` complete, package imports OK |

## Remaining Setup (Enterprise Controls)

These are documented in [APPROACH.md](APPROACH.md) but not yet deployed:

| Control | Status |
|---|---|
| VPC Service Controls | Not configured |
| Private Service Connect | Not configured (using Private Google Access for now) |
| Cloud NGFW / Palo Alto | Not deployed |
| Cloud VPN + on-prem proxy | Not configured |
| Squid egress proxy | Not deployed |
| Cloud Audit Log sinks to BigQuery | Not configured |
| Alert policies | Not configured |
| SandboxBench validation | Not run |

## Teardown

```bash
PROJECT=YOUR_PROJECT_ID

# Delete VM
gcloud compute instances delete mythos-harness \
  --zone=us-central1-a --project=$PROJECT --quiet

# Delete NAT and router
gcloud compute routers nats delete mythos-nat \
  --router=mythos-router --region=us-central1 --project=$PROJECT --quiet
gcloud compute routers delete mythos-router \
  --region=us-central1 --project=$PROJECT --quiet

# Delete firewall rules
gcloud compute firewall-rules delete mythos-deny-all-ingress --project=$PROJECT --quiet
gcloud compute firewall-rules delete mythos-allow-iap-ssh --project=$PROJECT --quiet

# Delete subnet and VPC
gcloud compute networks subnets delete mythos-subnet \
  --region=us-central1 --project=$PROJECT --quiet
gcloud compute networks delete mythos-vpc --project=$PROJECT --quiet

# Delete service accounts
gcloud iam service-accounts delete \
  mythos-orchestrator-sa@${PROJECT}.iam.gserviceaccount.com --project=$PROJECT --quiet
gcloud iam service-accounts delete \
  mythos-sandbox-sa@${PROJECT}.iam.gserviceaccount.com --project=$PROJECT --quiet
```
