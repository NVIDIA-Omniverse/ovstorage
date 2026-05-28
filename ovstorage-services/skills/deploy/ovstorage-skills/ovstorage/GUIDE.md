# Omniverse Storage APIs — Deployment Skill (v1.0.0)

---

## Purpose

This skill enables you to guide developers through deploying the Omniverse Storage APIs stack.

**The fundamental model:** Every Omniverse Storage service (Discovery, Storage, Notifications, Navigator) is an independent building block. Developers start with the smallest useful combination and add services incrementally — on any cluster type, at any time. There are no "deployment tiers" to migrate between. Either service stack (Example Adapter or Production Adapter) runs on any Kubernetes distribution.

**Deployment vs API guidance are separate concerns:**
- **Deployment** → Helm charts, values files, ingress, secrets, service dependencies → `references/deployment/`
- **API usage** → endpoints, request/response schemas, gRPC/REST patterns → `references/apis/`

**NGC Catalog links** — when a developer asks where to find more information or download specs:
- **Full collection** (all services, charts, API specs): https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/collections/storage_apis
- **Storage API specs**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/storage-api
- **Notifications Consumer API specs**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/notifications-consumer-api
- **Notifications Aggregation API specs**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/notifications-aggregation-api
- **Permissions API specs**: https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/permission-api

---

## Gather Deployment Parameters First

**Before generating any commands or configuration, walk through these steps in order.**
Do not assume defaults — the developer may have naming conventions, existing namespaces, or
multi-tenant requirements that differ from any example.

> **STOP — Do not generate commands until the developer has answered.**
> If the developer has not provided a namespace, do not assume one. Do not use
> `storage-apis-dev`, `storage-apis`, or any other namespace as a "default" or "assuming"
> value in commands. Ask the question and wait. You may describe the deployment flow
> conceptually while waiting, but do not emit any `kubectl`, `helm`, or YAML that contains
> a namespace until the developer has explicitly provided one.

### Step 1 — Collect Core Parameters

| Parameter | What to ask | Used in |
|-----------|------------|---------|
| **Namespace** | "What Kubernetes namespace would you like to use?" | Every `kubectl` / `helm` command, K8s YAML manifests, internal DNS names |
| **NGC API key** | "Do you have your NGC API key ready? (export it as `NGC_API_KEY`)" | Image pull secret creation, `helm fetch` |
| **Registry path** | "Are you deploying from the production NGC registry (`nvcr.io/nvidia/omniverse`) or a private registry?" | `image.repository` in every values file |

### Step 2 — Storage Adapter

Ask which storage adapter the developer wants:

- **Example storage adapter** — Python filesystem reference implementation for learning the API and custom adapter development. NOT for production.
- **S3/Azure production storage adapter** — NVIDIA pre-built adapter for S3 or Azure Blob Storage. Production-ready, composable.

### Step 3 — Cluster / Platform

If the developer has not already stated their cluster target, ask explicitly:
"What Kubernetes platform are you deploying to? (e.g., MicroK8s, EKS, AKS, GKE, bare metal)"

> **CSP account warning:** If the developer names a cloud provider (AWS, Azure, GCP),
> confirm they have an active cloud account and access keys ready (e.g., AWS access key
> + secret, Azure storage account key, GCP service account). These are needed for cloud
> storage backend configuration and are separate from the NGC API key.

### Step 4 — Services

Ask which services beyond the minimum (Storage + Discovery):
Notifications, Auth (Envoy Auth Extension), Storage Navigator, Contour ingress, Integration Tests.
See the Composability Pattern section for the full list.

### Step 5 — Deploy Method

Always ask this question explicitly, even when the developer has provided all other parameters or says "set it up for me" — "set it up for me" is ambiguous between automated execution and script generation:

"Would you like me to deploy this for you automatically (I'll run the scripts on your behalf), or generate the scripts for you to run manually?"

**Either way, always generate deployment scripts first.** See
`references/deployment/script-templates.md` for the full template structure.

- A **deployment directory** containing:
  - `.env.example` — template with all required variables (empty values, comments explaining each)
  - `.env` — filled with the developer's actual values (**must be gitignored**)
  - Numbered deployment scripts (shell scripts that source `.env` and run `helm fetch` / `helm install` / `kubectl apply`)
  - `deploy-all.sh` — master orchestrator that runs all scripts in order
  - `99-validate.sh` — post-deployment validation
  - Per-service values YAML overrides in `values/`
- If **automated**: execute `deploy-all.sh` on the developer's behalf. This runs each
  numbered script in order, validating each step. The developer sees all output and can
  debug any failures. The scripts remain for future manual re-runs.
- If **manual**: provide the scripts and explain the execution order.

> **IMPORTANT — Always deploy through scripts, never ad-hoc commands.**
> Whether deploying on the developer's behalf or guiding them manually, all deployment
> commands must go through the generated scripts. Do not run bare `helm install` or
> `kubectl apply` commands outside of scripts. If scripts already exist in the deployment
> directory, use them. If they don't exist yet, create them first using the templates from
> `references/deployment/script-templates.md`, then execute them. This ensures deployments
> are reproducible, debuggable, and re-runnable.

> The `.env` and `.env.example` files go at the root of the deployment directory alongside
> the scripts and values files. Add `.env` to `.gitignore` immediately — it contains
> credentials (NGC API key, cloud storage keys) that must never be committed.

### What the NGC API Key Is

The NGC API key (starts with `nvapi-`) is a **registry credential** that authenticates
access to two NVIDIA services:

1. **Helm chart downloads** from `helm.ngc.nvidia.com` — used in `helm fetch` commands
   with `--username='$oauthtoken' --password=${NGC_API_KEY}`
2. **Container image pulls** from `nvcr.io` — used via a Kubernetes `docker-registry`
   secret (`ngcpull-secret`) so the cluster can pull images at deploy time

Both services are part of the [NGC Catalog](https://catalog.ngc.nvidia.com) — this is
where developers browse and download Helm charts and container images. The same API key
works for both. Developers generate their key at https://ngc.nvidia.com/signin
with **NGC Catalog** and **NVIDIA Private Registry** permissions enabled.

> **Two different NGC URLs — don't mix them up:**
> - **https://catalog.ngc.nvidia.com** — browse and download charts, images, and API specs
> - **https://ngc.nvidia.com/signin** — sign in to generate or manage your API key

> **Do not confuse the NGC API key with an application-level API key.** It is not used
> by deployed services at runtime — it is only needed during `helm fetch` and by the
> Kubernetes image pull secret to download charts and container images.

Once you have the namespace, use it consistently in **every** command, YAML manifest, and Helm
value you generate. Never use a hardcoded namespace from the reference files — always substitute
the developer's chosen namespace. The reference files use `<your-namespace>` as a placeholder;
replace it everywhere with the developer's answer.

---

## Choosing Your Starting Point

The deployment model has **two independent axes**. Any combination is valid — both adapters
run on any Kubernetes cluster.

```
AXIS 1 — Cluster / Platform
│
│  Any Kubernetes distribution works: MicroK8s, EKS, AKS, GKE, bare metal, etc.
│  The cluster type affects command prefixes (microk8s kubectl vs kubectl)
│  and how ingress is configured. All Helm values, Discovery config, and service
│  configurations are identical across cluster types.
│  Ask explicitly if not stated by the developer.
│
AXIS 2 — Storage Adapter (your main decision)
│
├─ Example Storage Adapter
│     Python filesystem adapter — a reference implementation for learning the API
│     and as a starting point for custom adapter development. NOT for production.
│     Deployed as raw K8s YAML (not Helm)
│     Ports: gRPC 50051 / REST 8011  |  API prefix: /v1beta/
│     Minimum services: Python adapter + Discovery
│     See: references/deployment/example-adapter-stack.md
│
└─ S3/Azure Production Storage Adapter
      NVIDIA pre-built adapter (S3 or Azure Blob) — composable and production-ready.
      Start with Storage + Discovery (minimum), then add services incrementally:
      Notifications, Auth, Navigator, Contour — as needs require. Not all services required.
      Deployed via Helm chart (storage-service from NGC)
      Ports: gRPC 8011 / REST 8012  |  API prefix: /v1alpha/
      See: references/deployment/production-adapter-stack.md

Common starting points:
  "minimal on my machine" / local dev  →  Example Storage Adapter (ALWAYS — do not suggest
                                           the production adapter for minimal/local requests)
  Learning the API / no cloud storage  →  Example Storage Adapter
  Cloud storage, any cluster           →  S3/Azure Production Storage Adapter (Storage + Discovery minimum)
  Custom adapter development           →  Start with Example Storage Adapter as test target,
                                           implement against the gRPC + REST spec
                                           See references/development/custom-storage-adapter.md
```

> **When a developer asks for "minimal", "simplest", or "on my machine":** always guide to
> the Example Storage Adapter. Do not recommend or mention the S3/Azure Production Storage
> Adapter as an alternative — it requires cloud credentials and is not what "minimal" means.

> **Any combination is valid.** A developer can run the NVIDIA adapter on MicroK8s with
> real S3 or Azure credentials for local integration testing. A developer who starts with
> the Python adapter can swap in the NVIDIA adapter, add Notifications or Navigator, and
> later move to a different cluster — without rebuilding any service.

---

## Service Building Blocks

Each service below is independently deployable. Any combination is valid. You do not need
all services — start with the ones that match your current need and add more over time.
The Discovery Service is always required as the integration point that ties everything together.

### Discovery Service — REST Only, Single Endpoint

> **CRITICAL — Discovery has exactly one endpoint. Do not invent others.**
>
> Discovery exposes **one endpoint** over **REST only** (no gRPC):
>
> ```
> GET http(s)://{discovery-host}/api/v1/services
> ```
>
> This returns a single JSON object listing all registered services and their connection
> details. When authentication is deployed, Discovery also serves
> `GET /api/v1/auth-config` (always publicly accessible). **These are the only two paths
> Discovery serves.** Do not reference, name, or mention any other paths — not even to
> say they do not exist, because naming nonexistent paths causes confusion.
>
> Clients (Kit, Client Library, custom apps) connect to this one URL to learn where
> every other service lives. The `OMNI_STORAGE_DISCOVERY` environment variable should
> be set to the Discovery base URL (e.g., `http://localhost:8080` or
> `https://storage.example.com`) — clients append `/api/v1/services` automatically.

### Service Components

| Service | Type | Purpose | Ports |
|---------|------|---------|-------|
| **Discovery** | REST only | Single JSON endpoint: `GET /api/v1/services` | 8080 |
| **Storage (Python example)** | gRPC + REST | File ops via local filesystem adapter | REST: 8011 / gRPC: 50051 |
| **Storage (NVIDIA adapter)** | gRPC + REST | File ops via S3/Azure backend | gRPC: 8011 / REST: 8012 / Metrics: 8013 |
| **Notifications (Aggregation)** | gRPC | Publishers send events | gRPC: 50051 |
| **Notifications (Consumer)** | gRPC + REST | Subscribers receive events | gRPC: 50052 / REST: 8081 |
| **Storage Navigator** | REST (Web UI) | Browser-based file manager for storage resources | 8080 |
| **Envoy Auth Extension** | — | OIDC authentication proxy for the stack | — |
| **Contour** | — | Ingress / load balancer for external access | — |
| **Permissions** _(not yet released)_ | gRPC + REST | Authorization checks (PARC model). API spec available for custom adapter development — see `references/apis/permissions-api.md` and `references/development/custom-permissions-adapter.md`. No pre-built service released yet. | — |

### Helm Chart Names vs Container Image Names

The Helm chart name and the container image name are **not always the same**. Always use the correct name for each context.

> **v1.0.0 release versions** — The table below reflects the v1.0.0 GA release. When newer versions are available, update this table and the corresponding `helm fetch` commands in the reference files.

| Service | Helm Chart Name | Chart Version | Container Image | Image Tag |
|---------|----------------|---------------|-----------------|-----------|
| Storage (NVIDIA adapter) | `storage-service` | 1.0.2 | `storage-service` | 1.0.2 |
| Discovery | `discovery-service` | 2.3.8 | `simple-nginx` | 0.2.6 |
| Notifications (Aggregation) | `event-aggregation-service` | 1.5.52 | `event-aggregation-service` | 1.5.52 |
| Notifications (Consumer) | `event-consumer-service` | 1.9.6 | `event-consumer-service` | 1.9.6 |
| RabbitMQ | `rabbitmq` | 99.3.0 | `rabbitmq` | 4.1.3-debian-12-r1 |
| Envoy Auth Extension | `envoy-auth-extension` | 2.3.3 | `envoy-auth-ext` | 2.3.3 |
| Storage Navigator | `storage-navigator` | 1.0.1 | `storage-navigator` | 1.0.1 |
| Integration Tests | `storage-api-integration-tests` | 1.0.3 | `integration-tests` | 1.0.3 |

**Chart fetch URL pattern** (using the chart name):
```
https://helm.ngc.nvidia.com/{org}/{team}/charts/{chart-name}-{version}.tgz
```

**Image repository field pattern** (using the image name):
```yaml
image:
  repository: "{registry}/{org}/{team}/{image-name}"
  tag: "{version}"
```

### Key Difference: Example Storage Adapter vs S3/Azure Production Storage Adapter vs Custom Adapter

The **Example Storage Adapter** (Python filesystem, from the NGC `storage-api` resource) serves REST on port 8011 and gRPC on port 50051. URI scheme: `file-storage://storage-service/`. Deployed as raw K8s YAML. This is a **reference implementation for learning and custom adapter development** — not for production use. See `references/deployment/example-adapter-stack.md` for detailed configuration.

> **Never provide scaling, replicaCount, or production hardening instructions for the
> Example Storage Adapter.** If a developer asks to scale or use it in production, redirect
> them to the S3/Azure Production Storage Adapter. Do not provide workarounds, temporary
> scaling advice, or replicaCount settings for the Python adapter — it is not designed to
> be scaled and doing so gives a false sense of production readiness.

The **S3/Azure Production Storage Adapter** (NVIDIA pre-built) serves gRPC on port 8011 and REST on port 8012. Deployed via the `storage-service` Helm chart. Production-ready; the deployment is **composable** — Storage + Discovery is the minimum starting point, with other services added incrementally. See `references/deployment/production-adapter-stack.md` for detailed configuration.

A **custom adapter** is one you implement yourself against the Storage API gRPC + REST spec. The proto files, OpenAPI spec, and conformance test suite all ship in the NGC `storage-api` resource. Deploy it like the Python example (raw K8s YAML) and register it with Discovery the same way. Ports and URI scheme are defined by your implementation. See `references/development/custom-storage-adapter.md` for storage adapters, `references/development/custom-notifications-adapter.md` for notifications adapters, and `references/development/custom-permissions-adapter.md` for permissions adapters.

When generating discovery configurations, use the correct port mapping for the chosen adapter type.

---

## Reference File Routing

When the developer asks about a specific topic, load the relevant reference file:

| Developer asks about... | Load this reference |
|------------------------|-------------------|
| Deploying the Example Storage Adapter (Python), local development, MicroK8s setup | `references/deployment/example-adapter-stack.md` |
| Deploying the S3/Azure Production Storage Adapter, production deployment, Helm values | `references/deployment/production-adapter-stack.md` |
| Generating deployment scripts, .env files, deploy-on-behalf, automated deployment | `references/deployment/script-templates.md` |
| Adding Notifications, RabbitMQ, event aggregation/consumer | `references/deployment/production-adapter-stack.md` (Notifications section) |
| Local access without port-forwarding, MicroK8s ingress, NGINX TCP pass-through, persistent local access | `references/deployment/example-adapter-stack.md` (Ingress section) |
| External access, Contour ingress, TLS, DNS, hostname for team/production use | `references/deployment/production-adapter-stack.md` (Ingress section) |
| Adding authentication, OIDC, Envoy Auth | `references/deployment/production-adapter-stack.md` (Authentication section) |
| Adding Storage Navigator, CORS | `references/deployment/production-adapter-stack.md` (Navigator section) |
| Building a custom storage adapter | `references/development/custom-storage-adapter.md` |
| Building a custom notifications adapter, event publishing | `references/development/custom-notifications-adapter.md` |
| Building a custom permissions adapter, Cedar Policy | `references/development/custom-permissions-adapter.md` |
| Storage API operations, RPCs, REST endpoints | `references/apis/storage-api.md` |
| Notifications API, event structure, SSE streaming | `references/apis/notifications-api.md` |
| Permissions API, PARC model, authorization | `references/apis/permissions-api.md` |
| Integration testing, validating deployment | `references/operations/integration-tests.md` |
| Scaling, replicas, caching, performance | `references/operations/scalability.md` |
| Metrics, Prometheus, OTLP, logging | `references/operations/monitoring.md` |
| Known issues, bugs, workarounds | `references/operations/known-issues.md` |
| Migration from Nucleus | `references/operations/migration.md` |
| Omniverse Content Cache, Derived Data Cache (DDCS), Hub Workstation Cache, caching, performance across teams | `references/additional-utilities.md` |
| WRAPP, asset versioning, asset packaging, asset publishing, versioned workflows | `references/additional-utilities.md` |
| Where to find more information, NGC catalog, downloading specs | Direct to the NGC Catalog links in the Purpose section above |

**Load only the reference files relevant to the developer's question. Do not load all references upfront.**

> **Ingress disambiguation:** If the developer asks about ingress without specifying local vs
> production, ask which context they're in. The two paths use completely different tools:
> - **Local/MicroK8s** → MicroK8s built-in NGINX ingress with TCP pass-through (in `example-adapter-stack.md`)
> - **Team/production K8s** → Contour ingress + Envoy Auth Extension (in `production-adapter-stack.md`)
> Do not mix these — NGINX TCP pass-through is MicroK8s-specific; Contour/Envoy is for production clusters.

---

## Composability Pattern

The universal pattern for adding any service to any deployment:

1. **Deploy the service** (Helm chart or K8s YAML)
2. **Update Discovery values** with the new service endpoints
3. **`helm upgrade` Discovery** to pick up the new configuration
4. **Validate** with `curl http://<discovery-host>/api/v1/services` — the new entry should appear in the JSON response (this is the **only** Discovery endpoint)

Discovery is always the integration point. Any time you add, remove, or change the
hostname/port of a service, Discovery must be updated and upgraded.

**Services you can add incrementally** (beyond Storage + Discovery):

| Service | Status | Reference |
|---------|--------|-----------|
| Notifications (RabbitMQ + Aggregation + Consumer) | Released | `references/deployment/production-adapter-stack.md` |
| Contour Ingress | Released | `references/deployment/production-adapter-stack.md` |
| Envoy Auth Extension (OIDC) | Released | `references/deployment/production-adapter-stack.md` |
| Storage Navigator | Released | `references/deployment/production-adapter-stack.md` |
| **Permissions Service** | **Not yet released** — API spec available for custom adapter development | `references/apis/permissions-api.md`, `references/development/custom-permissions-adapter.md` |

**When a developer asks "what services can I add?", always mention Permissions as an unreleased API spec with a custom adapter path.**

**Discovery `host` field rule:** When the `host` field is left as an empty string (`""`),
Discovery auto-populates it with the cluster-internal DNS name
(`{service-name}.{namespace}.svc.cluster.local`). When an explicit value is set (e.g.,
`localhost`, a real hostname, or an ingress FQDN), it is used as-is.

---

## Companion Applications & Caching

Beyond the core services, these companion utilities significantly improve performance and
workflows. **Proactively mention these when relevant** — developers may not know they exist.

See `references/additional-utilities.md` for full details and NGC links.

| Utility | Type | When to Mention |
|---------|------|-----------------|
| **Omniverse Content Cache** | Server-side shared cache (Helm chart) | Multi-user teams reading the same USD assets — caches content reads so one user's fetch benefits everyone |
| **Derived Data Cache (DDCS)** | Server-side shared cache (Helm chart) | Multi-user teams rendering the same scenes — caches generated rendering data to improve time-to-open |
| **Hub Workstation Cache** | Local workstation cache (standalone app) | Any developer wanting faster local USD iteration — runs locally, benefits Kit apps and Client Library |
| **WRAPP** | CLI tool + library | Versioned asset workflows — packaging, publishing, and consuming asset packages across teams. Works as a library alongside Storage APIs with any compatible backend (S3, Nucleus, custom adapter) |

**When a developer asks about performance, caching, or scaling**, check whether server-side
caching (Content Cache / DDCS) or local caching (Hub Workstation Cache) would help before
jumping to replica scaling.

**When a developer asks about asset workflows, versioning, or publishing**, mention WRAPP
as the purpose-built tool for versioned asset packaging.

---

## Post-Deployment Validation

After deploying services, validate the deployment in this order. **Always run per-service
direct validation even when integration tests are also deployed** — they test different things.

### Step 1 — Discovery Connectivity

Confirm Discovery is reachable and returns the expected services:

```bash
curl http(s)://{discovery-host}/api/v1/services
```

Verify:
- The JSON response lists **every service you deployed**
- Service URLs match the deployment topology:
  - **No ingress:** cluster-internal routes (`http://{service}.{namespace}.svc.cluster.local:{port}`)
  - **With ingress:** ingress-accessible FQDNs (`https://{dns-url}`)
- No services are missing or have wrong ports

### Step 2 — Per-Service Direct Validation

| Service | Validation Method | Documented? |
|---------|------------------|-------------|
| **Example Storage Adapter** | `curl /v1beta/capabilities/services` + file upload/download round-trip | Yes — see `references/deployment/example-adapter-stack.md` |
| **S3/Azure Production Storage Adapter** | `curl /v1alpha/capabilities/services` + `curl /v1alpha/filefolder/list/{resource}` | Yes — see `references/deployment/production-adapter-stack.md` |
| **Notifications (Aggregation + Consumer)** | Two-terminal test: Terminal 1 subscribes to SSE event stream, Terminal 2 triggers a storage write. Verify events appear in Terminal 1. | Yes — see `references/deployment/production-adapter-stack.md` Notifications validation section |
| **RabbitMQ** | Pod is Running and healthy: `{kubectl} get pods -n {namespace} \| grep rabbitmq` | Health check only — no direct API validation documented |
| **Envoy Auth Extension** | Pod is Running and healthy. Validated indirectly via the auth-config endpoint on Discovery (see below). | Health check only — validated through Discovery |
| **Contour** | Pod is Running. Verify the external IP is reachable: `{kubectl} get svc -n contour-system envoy` then `ping`, `curl`, or `dig` the emitted IP/hostname. | Yes — IP reachability check |
| **Storage Navigator** | `curl http(s)://{navigator-host}` — expect HTTP 200 with an HTML page containing `<title>Storage Navigator</title>` | Yes — simple HTTP check |

> **Do not hallucinate validation steps.** If a service is marked as "health check only",
> say so explicitly. Do not fabricate curl endpoints, health check paths, or
> readiness probe URLs that are not documented above.

### Step 3 — Auth-Config Validation (when Auth is deployed)

The `/api/v1/auth-config` endpoint is served by Discovery (not by Envoy Auth Extension
directly). It is **always publicly accessible** — it must be reachable without
authentication so clients can discover the OIDC configuration needed to authenticate.

```bash
curl https://{DNS_URL}/api/v1/auth-config
```

Expected response structure (client IDs and tenant IDs will vary per deployment):

```json
{
  "clients": {
    "client_library": {
      "client_id": "<your-client-id>",
      "scope": "openid profile email offline_access <your-client-id>/.default"
    },
    "default": {
      "client_id": "<your-client-id>",
      "scope": "openid profile email offline_access <your-client-id>/.default"
    },
    "navigator": {
      "client_id": "<your-client-id>",
      "scope": "openid profile email offline_access <your-client-id>/.default"
    }
  },
  "openid_configuration": "https://login.microsoftonline.com/<your-tenant-id>/v2.0/.well-known/openid-configuration"
}
```

Then verify that unauthenticated requests to protected endpoints are rejected:

```bash
curl -vvv https://{DNS_URL}/api/v1/services
# expect HTTP 401 with server: envoy
```

### Step 4 — Integration Tests (when Discovery + Storage + Notifications are deployed)

When all three core services are running, deploy the `storage-api-integration-tests` Helm
chart. This validates cross-service interactions (storage events → notifications, permission
enforcement, etc.). See `references/operations/integration-tests.md` for full configuration.

**Integration tests complement but do not replace per-service validation.** Always run
Steps 1-3 first, then deploy integration tests as the final validation layer.

---

## Troubleshooting

In commands below, substitute `{kubectl}` with `kubectl` (standard K8s) or `microk8s kubectl`
(MicroK8s), and `{namespace}` with your deployment namespace.

---

### General: Pods not starting

```bash
# Check pod status and events
{kubectl} get pods -n {namespace}
{kubectl} describe pod -n {namespace} <pod-name>
{kubectl} logs -f deployment/<service-name> -n {namespace}
```

Common pod failure reasons and what to look for in `describe pod`:

| Status | Likely cause | Resolution |
|--------|-------------|------------|
| `ImagePullBackOff` | Pull secret missing, wrong registry, or image tag not found | See NGC pull failures below |
| `Pending` (no node) | Insufficient cluster resources | Check node capacity |
| `Pending` (PVC not bound) | Storage class issue or addon not ready | See PVC troubleshooting below |
| `CrashLoopBackOff` | Application misconfiguration | Check `logs` for startup errors |
| `OOMKilled` | Insufficient memory limits | Increase pod memory limits in values |

---

### General: Discovery returns empty or wrong URLs

- Verify your Discovery values YAML has correct service entries and the right ports
- Check that `host` field is correct: empty string → cluster-internal auto-hostname;
  explicit value (e.g., `localhost` or a real hostname) → used as-is
- After updating values, upgrade and wait for the pod to restart:
  ```bash
  {helm} upgrade discovery-service . -f <values>.yaml --namespace {namespace}
  {kubectl} rollout status deployment/discovery-service -n {namespace}
  curl http://<discovery-host>/api/v1/services
  ```

---

### General: NGC pull failures

```bash
# Verify pull secret exists in the right namespace
{kubectl} get secret ngcpull-secret -n {namespace}

# Test NGC credentials directly
docker login nvcr.io -u '$oauthtoken' -p "${NGC_API_KEY}"

# Verify pull secret server matches image.repository registry
{kubectl} get secret ngcpull-secret -n {namespace} -o jsonpath='{.data.\.dockerconfigjson}' \
  | base64 --decode | python3 -m json.tool
```

The `--docker-server` used to create the secret must exactly match the hostname at the start
of `image.repository` in your values file (always `nvcr.io` for NGC production).

---

### General: Port-forward drops or times out

`kubectl port-forward` is not production-grade — connections drop after idle periods or
cluster restarts. It is only intended for local development and validation.

```bash
# Check if port-forward processes are still alive
ps -ef | grep "port-forward"

# Restart all port-forwards for a namespace
{kubectl} port-forward -n {namespace} service/discovery-service 8080:8080 &
{kubectl} port-forward -n {namespace} service/storage-service 8011:8011 &
```

For persistent external access, add ingress instead — see the deployment reference files.

---

### MicroK8s: `ImagePullBackOff` after `microk8s ctr image import`

This is the most common MicroK8s failure. The image was imported successfully but the pod
still cannot find it because the image name or tag in the manifest does not exactly match
what was imported.

```bash
# 1. Check the exact name stored after import
microk8s ctr image ls | grep storageapi

# 2. Compare to the image field in your manifest/values:
#    The manifest must use EXACTLY this name (including tag)
#    imagePullPolicy must be Never (not IfNotPresent or Always)

# 3. If names differ, re-import with the correct tag or update the manifest
docker save <image>:<tag> -o image.tar
microk8s ctr image import image.tar
microk8s ctr image ls | grep <image>
```

---

### MicroK8s: PVC stays `Pending` — `hostpath-storage` not ready

```bash
# Check addon status
microk8s status

# If hostpath-storage shows as disabled or not ready:
microk8s enable hostpath-storage
# Wait for the provisioner pod to be Running before creating PVCs:
microk8s kubectl get pods -n kube-system | grep hostpath

# Check PVC events for the actual error:
microk8s kubectl describe pvc storage-pvc -n <namespace>
```

If you created the PVC before the addon was ready, delete and recreate it:
```bash
microk8s kubectl delete pvc storage-pvc -n <namespace>
microk8s kubectl apply -f storage-service.yaml -n <namespace>
```

---

### MicroK8s: Inter-pod DNS not resolving

Symptom: pods cannot reach each other by service name (e.g., the storage service cannot
reach the Discovery service by cluster DNS).

```bash
# Verify dns addon is enabled and its pods are Running
microk8s status
microk8s kubectl get pods -n kube-system | grep dns

# Enable if needed (cluster restart may be required):
microk8s enable dns

# Test DNS resolution from inside a pod:
microk8s kubectl run -it --rm debug --image=busybox --restart=Never -n <namespace> \
  -- nslookup discovery-service.<namespace>.svc.cluster.local
```

---

### MicroK8s: `microk8s helm` vs standalone `helm` version conflicts

MicroK8s ships its own bundled `helm` via `microk8s enable helm`. This version may differ
from a system-installed `helm`. Symptoms include unexpected flags not being recognized or
chart template errors that work with one but not the other.

```bash
# Check which version MicroK8s helm uses:
microk8s helm version

# Check system helm:
helm version

# Use one consistently throughout your deployment. If MicroK8s helm is enabled,
# prefer microk8s helm to avoid path conflicts.
```

If you prefer to use system `helm` with MicroK8s, point it at the MicroK8s kubeconfig:
```bash
export KUBECONFIG=/var/snap/microk8s/current/credentials/client.config
helm upgrade --install ...
```

---

### MicroK8s: `microk8s kubectl` vs `kubectl` alias confusion

MicroK8s does not automatically add `kubectl` to your `PATH`. All commands in the local
deployment section use `microk8s kubectl`. If you have a separate `kubectl` installed, it
may point to a different cluster.

```bash
# Always use microk8s kubectl to target MicroK8s:
microk8s kubectl get nodes

# Or set up an alias for the session:
alias kubectl='microk8s kubectl'

# Or add the MicroK8s kubeconfig permanently:
microk8s config > ~/.kube/config   # WARNING: overwrites existing config
# Safer: merge configs using KUBECONFIG env var
export KUBECONFIG=~/.kube/config:/var/snap/microk8s/current/credentials/client.config
```

---

## Known Issues (v1.0.0)

| Issue | Workaround |
|-------|-----------|
| Notifications Services: writing outside Storage Service path won't produce update events | Use Storage APIs for both read and write to get consistent notifications |
| Auth token may expire and disconnect Kit streaming sessions | Start a new streaming session |
| Copy, Move, Rename, Create Folder not in Kit/Client Library | Use Storage Navigator for these operations |
| Multiple Storage replicas with caching may return stale reads | Use versioned object access or disable caching |
| `FILESERVICE_STATIC_DIR` env var ignored in K8s — files written to ephemeral storage and lost on restart | Pass the backend subcommand explicitly: `args: ["filesystem", "--static-dir", "/data/storage"]` |
| IRSA Web Identity Tokens not consumed on EKS — Helm chart injects AWS credentials but service doesn't consume them | Inject AWS credentials explicitly via K8s secret and reference via `extraEnvs` in Helm values |

---

## Reference File Index

```
references/
├── apis/
│   ├── storage-api.md          — Storage API gRPC/REST spec, RPCs, endpoints
│   ├── notifications-api.md    — Notifications API publisher/consumer spec
│   └── permissions-api.md      — Permissions API PARC model, Cedar Policy
├── deployment/
│   ├── example-adapter-stack.md    — Python filesystem adapter + Discovery (learning/dev)
│   ├── production-adapter-stack.md — NVIDIA S3/Azure adapter + full composable stack
│   └── script-templates.md         — Deploy scripts, .env, validation script templates
├── development/
│   ├── custom-storage-adapter.md       — Build custom storage adapters
│   ├── custom-notifications-adapter.md — Build custom notification adapters
│   └── custom-permissions-adapter.md   — Build custom permissions adapters
├── operations/
│   ├── monitoring.md          — Prometheus metrics, OTLP, logging config
│   ├── integration-tests.md   — Integration test Helm chart
│   ├── scalability.md         — Replica sizing, cache tuning
│   ├── known-issues.md        — Current known issues and workarounds
│   └── migration.md           — Nucleus migration tool
├── overview.md
├── architecture.md
├── quickstart.md
├── changelog.md
└── additional-utilities.md    — Caches (Content, DDCS, Workstation) + WRAPP versioned workflows
```
