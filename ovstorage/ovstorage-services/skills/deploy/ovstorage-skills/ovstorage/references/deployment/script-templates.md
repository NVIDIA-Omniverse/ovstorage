# Deployment Script Templates

When generating deployment scripts for a developer (either for manual use or automated
deploy-on-behalf), use the templates below as the starting structure. Adapt service
sections based on which services the developer selected.

---

## Directory Structure

Generate this layout in the developer's chosen deployment directory:

```
ovstorage-deploy/
├── .env.example          # Template — commit this
├── .env                  # Filled with real values — NEVER commit (gitignored)
├── .gitignore            # Ignores .env
├── 00-setup.sh           # Namespace, pull secret, chart fetches
├── 01-deploy-storage.sh  # Storage Service
├── 02-deploy-discovery.sh # Discovery Service
├── 03-deploy-rabbitmq.sh  # RabbitMQ (if Notifications selected)
├── 04-deploy-notifications.sh # Event Aggregation + Consumer (if selected)
├── 05-deploy-contour.sh   # Contour ingress (if selected)
├── 06-deploy-auth.sh      # Envoy Auth Extension (if selected)
├── 07-deploy-navigator.sh # Storage Navigator (if selected)
├── 08-deploy-integration-tests.sh # Integration tests (if selected)
├── 99-validate.sh         # Post-deployment validation
├── deploy-all.sh          # Master orchestrator — runs all in order
├── values/
│   ├── storage-values.yaml
│   ├── discovery-values.yaml
│   ├── rabbitmq-values.yaml       # if Notifications
│   ├── event-aggregation-values.yaml # if Notifications
│   ├── event-consumer-values.yaml   # if Notifications
│   ├── ingress-values.yaml          # if Contour
│   ├── oidc-config.yaml             # if Auth
│   ├── envoy-values.yaml            # if Auth
│   ├── navigator-values.yaml        # if Navigator
│   ├── integration-tests-values.yaml # if integration tests
│   └── observability-values.yaml    # optional — logging, metrics, OTLP
└── charts/                # Fetched Helm chart tarballs (gitignored)
```

---

## .env.example

This is the template. The developer copies it to `.env` and fills in real values.
Include comments explaining each variable. Only include variables relevant to the
developer's selected services.

```bash
# =============================================================================
# Omniverse Storage APIs — Deployment Configuration
# Copy this file to .env and fill in your values. NEVER commit .env to git.
# =============================================================================

# --- Core (required) ---
NAMESPACE=                    # Kubernetes namespace (e.g., storage-apis, omni-prod)
NGC_API_KEY=                  # NGC API key starting with nvapi- (for chart downloads and image pulls)
KUBECTL=kubectl               # Use "microk8s kubectl" for MicroK8s

# --- Storage Backend (required for S3/Azure Production Storage Adapter) ---
# For S3:
S3_BUCKET_NAME=               # e.g., my-omniverse-bucket
S3_REGION=                    # e.g., us-west-2
S3_ENDPOINT=                  # e.g., https://my-omniverse-bucket.s3.us-west-2.amazonaws.com
BUCKET_ACCESS_KEY_ID=         # AWS access key ID
BUCKET_SECRET_ACCESS_KEY=     # AWS secret access key

# For Azure (uncomment if using Azure instead of S3):
# AZ_STORAGE_ACCOUNT=         # e.g., omnidata
# AZ_BLOB_STORAGE_KEY=        # Azure storage account key

# --- Notifications (if deploying Notifications) ---
RABBITMQ_PASSWORD=            # Password for RabbitMQ admin user
# For S3 bucket notifications via SQS:
# SQS_QUEUE_URL=              # e.g., https://sqs.us-west-2.amazonaws.com/123456789/my-queue
# SQS_REGION=                 # e.g., us-west-2
# SQS_ACCESS_KEY_ID=          # (can reuse BUCKET_ACCESS_KEY_ID if same IAM user)
# SQS_SECRET_ACCESS_KEY=      # (can reuse BUCKET_SECRET_ACCESS_KEY if same IAM user)

# --- Ingress (if deploying Contour) ---
# DNS_URL=                    # e.g., storage.example.com
# TLS_CERT_PATH=              # Path to TLS certificate file
# TLS_KEY_PATH=               # Path to TLS private key file

# --- Auth (if deploying Envoy Auth Extension) ---
# OIDC_ISSUER=                # e.g., https://login.microsoftonline.com/{tenant-id}/v2.0
# OIDC_CLIENT_ID=             # OAuth2 client ID
```

---

## .gitignore

Always generate this in the deployment directory:

```
.env
charts/
*.tgz
```

---

## Script Conventions

Every script follows these conventions so a developer can read, debug, and rerun:

1. **`set -euo pipefail`** at the top — fail fast on errors
2. **Source `.env`** — all configuration comes from one place
3. **Print what is about to happen** before each command (`echo ">>> ..."`)
4. **Validate prerequisites** at the start (check kubectl access, namespace exists, etc.)
5. **Check result after each deploy** (`$KUBECTL rollout status` or `$KUBECTL get pods`)
6. **Exit with clear success/failure message**

```bash
#!/usr/bin/env bash
# <script-name>.sh — <what this script does>
# Usage: bash <script-name>.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.env"

echo "=== <Script Title> ==="

# --- Pre-checks ---
${KUBECTL} cluster-info > /dev/null 2>&1 || { echo "ERROR: Cannot reach cluster"; exit 1; }
${KUBECTL} get namespace "${NAMESPACE}" > /dev/null 2>&1 || { echo "ERROR: Namespace '${NAMESPACE}' does not exist. Run 00-setup.sh first."; exit 1; }

# --- Main ---
echo ">>> <Describe step>"
# <command>

echo ">>> Waiting for rollout..."
${KUBECTL} rollout status deployment/<service-name> -n "${NAMESPACE}" --timeout=120s

echo "=== DONE: <what completed> ==="
```

---

## 00-setup.sh Template

```bash
#!/usr/bin/env bash
# 00-setup.sh — Create namespace, pull secret, and fetch Helm charts
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.env"

echo "=== Setup: Namespace, Pull Secret, Charts ==="

# --- Create namespace ---
echo ">>> Creating namespace '${NAMESPACE}'..."
${KUBECTL} create namespace "${NAMESPACE}" --dry-run=client -o yaml | ${KUBECTL} apply -f -

# --- Create NGC pull secret ---
echo ">>> Creating NGC pull secret..."
${KUBECTL} create secret docker-registry ngcpull-secret \
  --docker-server="nvcr.io" \
  --docker-username='$oauthtoken' \
  --docker-password="${NGC_API_KEY}" \
  -n "${NAMESPACE}" \
  --dry-run=client -o yaml | ${KUBECTL} apply -f -

echo ">>> Verifying pull secret..."
${KUBECTL} get secret ngcpull-secret -n "${NAMESPACE}"

# --- Fetch Helm charts ---
echo ">>> Fetching Helm charts from NGC..."
mkdir -p "${SCRIPT_DIR}/charts"
cd "${SCRIPT_DIR}/charts"

CHARTS=(
  "storage-service-0.7.19"
  "discovery-service-2.3.2"
  # Add more charts based on selected services:
  # "rabbitmq-99.3.0"
  # "event-aggregation-service-1.4.13"
  # "event-consumer-service-1.7.16"
  # "envoy-auth-extension-2.3.2"
  # "storage-navigator-0.0.46"
  # "storage-api-integration-tests-0.7.4"
)

for CHART in "${CHARTS[@]}"; do
  if [ ! -d "${CHART%.tgz}" ] && [ ! -f "${CHART}.tgz" ]; then
    echo ">>> Fetching ${CHART}..."
    helm fetch "https://helm.ngc.nvidia.com/nvidia/omniverse/charts/${CHART}.tgz" \
      --username='$oauthtoken' --password="${NGC_API_KEY}"
    tar -xzf "${CHART}.tgz"
  else
    echo ">>> ${CHART} already fetched, skipping."
  fi
done

cd "${SCRIPT_DIR}"
echo "=== DONE: Setup complete ==="
```

---

## 01-deploy-storage.sh Template (S3 example)

```bash
#!/usr/bin/env bash
# 01-deploy-storage.sh — Deploy the S3/Azure Production Storage Adapter
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.env"

echo "=== Deploy: Storage Service ==="

# --- Pre-checks ---
${KUBECTL} get secret ngcpull-secret -n "${NAMESPACE}" > /dev/null 2>&1 || \
  { echo "ERROR: ngcpull-secret not found. Run 00-setup.sh first."; exit 1; }

# --- Create bucket credentials secret ---
echo ">>> Creating bucket credentials secret..."
${KUBECTL} create secret generic "${S3_BUCKET_NAME}-bucket-secret" \
  --from-literal=BUCKET_ACCESS_KEY_ID="${BUCKET_ACCESS_KEY_ID}" \
  --from-literal=BUCKET_SECRET_ACCESS_KEY="${BUCKET_SECRET_ACCESS_KEY}" \
  -n "${NAMESPACE}" \
  --dry-run=client -o yaml | ${KUBECTL} apply -f -

# --- Deploy via Helm ---
echo ">>> Installing Storage Service..."
helm upgrade --install storage-service "${SCRIPT_DIR}/charts/storage-service" \
  -f "${SCRIPT_DIR}/values/storage-values.yaml" \
  --namespace "${NAMESPACE}"

echo ">>> Waiting for rollout..."
${KUBECTL} rollout status deployment/storage-service -n "${NAMESPACE}" --timeout=180s

# --- Quick validation ---
echo ">>> Validating Storage Service..."
${KUBECTL} get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=storage-service

echo "=== DONE: Storage Service deployed ==="
```

---

## 02-deploy-discovery.sh Template

```bash
#!/usr/bin/env bash
# 02-deploy-discovery.sh — Deploy the Discovery Service
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.env"

echo "=== Deploy: Discovery Service ==="

# --- Deploy via Helm ---
echo ">>> Installing Discovery Service..."

# Build the helm command with optional layers
HELM_CMD="helm upgrade --install discovery-service ${SCRIPT_DIR}/charts/discovery-service"
HELM_CMD+=" -f ${SCRIPT_DIR}/values/discovery-values.yaml"

# Add ingress values if the file exists
if [ -f "${SCRIPT_DIR}/values/ingress-values.yaml" ]; then
  HELM_CMD+=" -f ${SCRIPT_DIR}/values/ingress-values.yaml"
fi

# Add OIDC config if the file exists
if [ -f "${SCRIPT_DIR}/values/oidc-config.yaml" ]; then
  HELM_CMD+=" -f ${SCRIPT_DIR}/values/oidc-config.yaml"
fi

HELM_CMD+=" --namespace ${NAMESPACE}"

echo ">>> Running: ${HELM_CMD}"
eval ${HELM_CMD}

echo ">>> Waiting for rollout..."
${KUBECTL} rollout status deployment/discovery-service -n "${NAMESPACE}" --timeout=120s

# --- Quick validation ---
echo ">>> Validating Discovery Service..."
${KUBECTL} get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=discovery-service

echo "=== DONE: Discovery Service deployed ==="
```

---

## 99-validate.sh Template

```bash
#!/usr/bin/env bash
# 99-validate.sh — Post-deployment validation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/.env"

echo "=== Post-Deployment Validation ==="
PASS=0
FAIL=0

check() {
  local name="$1"
  local cmd="$2"
  echo ""
  echo "--- Checking: ${name} ---"
  if eval "${cmd}" > /dev/null 2>&1; then
    echo "  PASS: ${name}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: ${name}"
    echo "  Command: ${cmd}"
    FAIL=$((FAIL + 1))
  fi
}

# --- Pod health ---
echo ">>> Checking pod status..."
${KUBECTL} get pods -n "${NAMESPACE}"
echo ""

# --- Discovery ---
check "Discovery pods running" \
  "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=discovery-service -o jsonpath='{.items[0].status.phase}' | grep -q Running"

# Port-forward Discovery for validation (background, killed on exit)
${KUBECTL} port-forward -n "${NAMESPACE}" service/discovery-service 18080:8080 &
PF_PID=$!
trap "kill ${PF_PID} 2>/dev/null" EXIT
sleep 2

check "Discovery GET /api/v1/services responds" \
  "curl -sf http://localhost:18080/api/v1/services"

echo ""
echo ">>> Discovery response:"
curl -s http://localhost:18080/api/v1/services | python3 -m json.tool 2>/dev/null || echo "(could not pretty-print)"

# --- Storage Service ---
check "Storage Service pods running" \
  "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=storage-service -o jsonpath='{.items[0].status.phase}' | grep -q Running"

# Port-forward Storage for validation
${KUBECTL} port-forward -n "${NAMESPACE}" service/storage-service 18012:8012 &
PF_STORAGE=$!
trap "kill ${PF_PID} ${PF_STORAGE} 2>/dev/null" EXIT
sleep 2

check "Storage Service REST /v1alpha/capabilities/services responds" \
  "curl -sf http://localhost:18012/v1alpha/capabilities/services"

# --- RabbitMQ (if deployed) ---
if ${KUBECTL} get deployment rabbitmq -n "${NAMESPACE}" > /dev/null 2>&1; then
  check "RabbitMQ pods running" \
    "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=rabbitmq -o jsonpath='{.items[0].status.phase}' | grep -q Running"
fi

# --- Event Aggregation (if deployed) ---
if ${KUBECTL} get deployment event-aggregation-service -n "${NAMESPACE}" > /dev/null 2>&1; then
  check "Event Aggregation pods running" \
    "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=event-aggregation-service -o jsonpath='{.items[0].status.phase}' | grep -q Running"
fi

# --- Event Consumer (if deployed) ---
if ${KUBECTL} get deployment event-consumer-service -n "${NAMESPACE}" > /dev/null 2>&1; then
  check "Event Consumer pods running" \
    "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=event-consumer-service -o jsonpath='{.items[0].status.phase}' | grep -q Running"
fi

# --- Contour (if deployed) ---
if ${KUBECTL} get deployment contour -n contour-system > /dev/null 2>&1; then
  check "Contour pods running" \
    "${KUBECTL} get pods -n contour-system -l app.kubernetes.io/name=contour -o jsonpath='{.items[0].status.phase}' | grep -q Running"

  ENVOY_IP=$(${KUBECTL} get svc envoy -n contour-system -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || \
             ${KUBECTL} get svc envoy -n contour-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
  if [ -n "${ENVOY_IP}" ]; then
    check "Contour external IP/hostname reachable" "ping -c 1 -W 3 ${ENVOY_IP}"
  else
    echo "  SKIP: No external IP/hostname on Contour envoy service yet"
  fi
fi

# --- Auth (if deployed) ---
if ${KUBECTL} get deployment envoy-auth-extension -n "${NAMESPACE}" > /dev/null 2>&1; then
  check "Envoy Auth Extension pods running" \
    "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=envoy-auth-extension -o jsonpath='{.items[0].status.phase}' | grep -q Running"

  # auth-config is served by Discovery — check via the already-open port-forward
  check "Discovery /api/v1/auth-config responds" \
    "curl -sf http://localhost:18080/api/v1/auth-config"
fi

# --- Storage Navigator (if deployed) ---
if ${KUBECTL} get deployment storage-navigator -n "${NAMESPACE}" > /dev/null 2>&1; then
  check "Storage Navigator pods running" \
    "${KUBECTL} get pods -n ${NAMESPACE} -l app.kubernetes.io/name=storage-navigator -o jsonpath='{.items[0].status.phase}' | grep -q Running"
  echo "  NOTE: Navigator has no automated validation — verify manually at https://navigator.{DNS_URL}"
fi

# --- Summary ---
echo ""
echo "==========================================="
echo "  Validation Complete: ${PASS} passed, ${FAIL} failed"
echo "==========================================="

if [ ${FAIL} -gt 0 ]; then
  echo ""
  echo "Some checks failed. Debug with:"
  echo "  ${KUBECTL} describe pod <pod-name> -n ${NAMESPACE}"
  echo "  ${KUBECTL} logs -f deployment/<service> -n ${NAMESPACE}"
  exit 1
fi
```

---

## deploy-all.sh Template

```bash
#!/usr/bin/env bash
# deploy-all.sh — Deploy the full stack in order
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================="
echo "  Omniverse Storage APIs — Full Deployment"
echo "============================================="
echo ""

# Check .env exists
if [ ! -f "${SCRIPT_DIR}/.env" ]; then
  echo "ERROR: .env file not found."
  echo "Copy .env.example to .env and fill in your values:"
  echo "  cp .env.example .env"
  exit 1
fi

source "${SCRIPT_DIR}/.env"
echo "Namespace: ${NAMESPACE}"
echo "kubectl:   ${KUBECTL}"
echo ""

# Run scripts in order — only run scripts that exist
for script in \
  00-setup.sh \
  01-deploy-storage.sh \
  02-deploy-discovery.sh \
  03-deploy-rabbitmq.sh \
  04-deploy-notifications.sh \
  05-deploy-contour.sh \
  06-deploy-auth.sh \
  07-deploy-navigator.sh \
  08-deploy-integration-tests.sh \
; do
  if [ -f "${SCRIPT_DIR}/${script}" ]; then
    echo ""
    echo ">>> Running ${script}..."
    bash "${SCRIPT_DIR}/${script}"
  fi
done

# Always run validation last
echo ""
echo ">>> Running validation..."
bash "${SCRIPT_DIR}/99-validate.sh"

echo ""
echo "============================================="
echo "  Deployment Complete"
echo "============================================="
```

---

## Usage in the Skill

When a developer asks for deployment (Step 5 — Deploy Method):

1. **Always generate**: `.env.example`, `.env` (with their values), `.gitignore`,
   per-service values YAML files, and numbered deploy scripts for the selected services.
   Include `deploy-all.sh` and `99-validate.sh`.

2. **Automated deploy**: After generating the files, execute `deploy-all.sh` which runs
   each script in order. The developer sees each step's output and can debug any failures.

3. **Manual deploy**: Generate all files and explain the execution order. The developer
   runs `deploy-all.sh` or individual scripts as needed.

4. **Adapt the templates**: These are starting points. Adjust based on:
   - The developer's selected services (omit scripts for unselected services)
   - Their cluster type (replace `kubectl` default with `microk8s kubectl` if MicroK8s)
   - Their storage backend (S3 vs Azure — different secrets and values)
   - Whether ingress/auth are selected (add or omit layered values files)

5. **Chart versions**: Always use the EA2 chart versions from the GUIDE.md chart table.
   Do not hardcode versions in the templates — pull them from the reference data.

---

## Optional: Observability Values Template

When a developer wants logging, metrics, or tracing, generate `values/observability-values.yaml` and layer it onto the relevant Helm install commands (e.g., `-f values/observability-values.yaml`).

```yaml
# observability-values.yaml — Optional logging, metrics, and tracing configuration
# Layer this onto storage-service and/or event services Helm installs.

# --- Storage Service observability ---
config:
  logging:
    level: "info"                # debug, info, warn, error
    # extra_targets: ""          # Additional log targets (comma-separated module=level)
    # backtrace: false           # Enable backtraces on errors

# Environment variable to enable Prometheus metrics export on the Storage Service:
extraEnvs:
  - name: OTEL_METRICS_EXPORTER
    value: "prometheus"
# Metrics are exposed at GET :8013/metrics when OTEL_METRICS_EXPORTER=prometheus

# --- Event services observability (Event Aggregation / Event Consumer) ---
# Uncomment and add to the event service values files if needed:
# telemetry:
#   enabled: true
#   otlp_tracing_endpoint: "http://otel-collector.observability.svc.cluster.local:4317"
#   otlp_metrics_endpoint: "http://otel-collector.observability.svc.cluster.local:4317"
#   otlp_logs_endpoint: "http://otel-collector.observability.svc.cluster.local:4317"
```

---

## Scalability Notes for storage-values.yaml

When generating `values/storage-values.yaml`, include these comments and optional config blocks to surface critical scalability constraints from the developer guide:

```yaml
# --- Scaling ---
# Sizing guideline: ~5 storage service replicas per 100 concurrent GPU clients.
# replicaCount: 1
# replicaMinCount: 1
# replicaScalingFactor: 1
# Formula: max(replicaMinCount, ceil(replicaCount / replicaScalingFactor))
#
# WARNING: When storageEvents (SQS or Azure Service Bus) is enabled, you MUST run
# replicaCount=1. Multiple replicas with notifications enabled will cause duplicate
# or missed events. Scale horizontally only when notifications are disabled.

# --- Caching (optional) ---
# config:
#   smallObjectCache:
#     timeToLive: 300       # seconds — cache TTL for small objects
#   statCache:
#     timeToLive: 60        # seconds
#     invalidateOnUpdate: true
#   listCache:
#     timeToLive: 60        # seconds
#     invalidateOnUpdate: true
```
