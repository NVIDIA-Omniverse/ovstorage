# Example Adapter Stack

## Overview

The Example Adapter Stack deploys the **Python filesystem reference implementation** of the Storage API Service alongside the **Discovery Service**. This stack is designed for learning, development, and testing custom adapters. It is **not intended for production use**.

The Python adapter is a reference implementation that demonstrates how to build a Storage API-compliant service. It serves files from a local filesystem using content and version trees, providing both REST and gRPC interfaces. By deploying it alongside Discovery, you get a complete working stack that Kit-based applications can connect to -- the same way they connect to Enterprise Nucleus Server or a full production deployment.

**Cluster-agnostic**: This stack runs on any Kubernetes distribution -- MicroK8s, EKS, AKS, GKE, bare metal K8s, or any other conformant cluster. The walkthrough uses MicroK8s as the example, but all Kubernetes manifests and Helm commands work on any cluster with minor adjustments (e.g., replacing `microk8s kubectl` with `kubectl`).

**Key characteristics of the Python adapter:**

- File operations: stat, read, write, enumerate, delete
- Multipart upload support for large files
- Directory operations: list, create, delete
- Versioning support: enumerate versions, read old versions
- Generic metadata store
- Ports: gRPC on **50051**, REST on **8011** (distinct from the NVIDIA production adapter which uses gRPC 8011 / REST 8012)

---

## Prerequisites

- **Python** 3.10, 3.11, or 3.12
- **Poetry** package manager
- **Docker** (version 28.4.0+ recommended) -- used to containerize the storage service adapter
- **Helm** -- used to deploy the Discovery Service chart
- **NGC Account** and the [NGC CLI](https://org.ngc.nvidia.com/setup/installers/cli) -- required to download the Storage API package and pull Helm charts/images
  - Your NGC API key must have permissions to access the registry
- **Any Kubernetes cluster** -- MicroK8s is recommended for local development but any K8s distribution works
  - If you are new to Kubernetes, work through [Install a local Kubernetes with MicroK8s](https://ubuntu.com/tutorials/install-a-local-kubernetes-with-microk8s#1-overview)

---

## Get the Storage API Package

Set up your [NGC CLI](https://docs.ngc.nvidia.com/cli/cmd.html) and download the Storage API specifications and Service Adapter example from NGC.

Resource versions are listed at: https://registry.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/storage-api/version

```bash
# specify the {version} you are trying to download
ngc registry resource download-version "nvidia/omniverse/storage-api:{version}"
```

Unzip and navigate to the filesystem example:

```bash
# unzip the package from where ngc download put it
unzip storage-api-{version}.zip -d ./storage-api-1.0.0-beta

# change to the directory to the filesystem example
cd ./storage-api-1.0.0-beta/filesystem_example
```

This package includes the API specifications and example code for a local filesystem service.

---

## Run Locally

You can run and test the service locally in Python before containerizing it. To persist data, create a directory such as `~/storage-data`.

### Installation

```bash
# Create virtual environment for poetry
python -m venv .poetry_venv

# Install poetry
.poetry_venv/bin/pip install poetry

# Install dependencies
.poetry_venv/bin/poetry install

# Run the installed entrypoint via poetry
.poetry_venv/bin/poetry run local-filesystem-service
```

Expected output:

```
2025-11-18 11:28:00,263 - INFO - gRPC Server launched on port 50051
2025-11-18 11:28:00,264 - INFO - Starting static server...
2025-11-18 11:28:00,272 - INFO - Started server process [362059]
2025-11-18 11:28:00,272 - INFO - Waiting for application startup.
2025-11-18 11:28:00,272 - INFO - Application startup complete.
2025-11-18 11:28:00,272 - INFO - Uvicorn running on http://0.0.0.0:8011 (Press CTRL+C to quit)
```

### Optional: Advanced Poetry Setup

You can activate the virtual environment poetry created to run `local-filesystem-service` directly:

```bash
$ .poetry_venv/bin/poetry env info
Virtualenv
Python:         3.10.12
Implementation: CPython
Path:           /home/username/storage-api/filesystem_example/.venv
Executable:     /home/username/storage-api/filesystem_example/.venv/bin/python
Valid:          True

Base
Platform:   linux
OS:         posix
Python:     3.10.12
Path:       /usr
Executable: /usr/bin/python3.10
```

```bash
source /home/username/storage-api/filesystem_example/.venv/bin/activate
local-filesystem-service
```

### Service Modes

**Combined Service (gRPC + REST):**

```bash
local-filesystem-service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

with BACKEND being `filesystem` as the only option in this version.

**gRPC Only:**

```bash
# via script
local-filesystem-grpc [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]

# via module
python -m local_filesystem_service.grpc_service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

**REST Only:**

```bash
# via script
local-filesystem-rest [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]

# via module
python -m local_filesystem_service.rest_service [COMMON_OPTIONS] BACKEND [BACKEND_OPTIONS]
```

### CLI Options

**Common Options** (apply to all backends):

- `--grpc-port`: Port for gRPC server (default: 50051)
- `--http-port`: Port for HTTP/REST server (default: 8011)
- `--reload`: Enable auto-reload for development (REST service only)

**Backend Subcommand Options** (for the `filesystem` backend):

- `--base-uri`: Base URI for resource addresses (default: `file-storage://fileservice`)
- `--static-dir`: Directory for file storage (default: system temp directory)
- `--folder-mode`: Folder simulation mode: `native`, `no_empty`, or `placeholder` (default: `native`)
- `--redirect-host`: Host for redirect URLs (default: `http://localhost`)
- `--redirect-port`: Port for redirect URLs (default: 8011)

**Example:**

```bash
# Get help first!
local-filesystem-service --help

# Start with filesystem backend (default settings)
local-filesystem-service

# Help for the specific parameters setting up the local filesystem
local-filesystem-service filesystem --help

# Start with custom configuration
local-filesystem-service filesystem --static-dir /data/storage

# The service is started as a python module, so this is equivalent:
python -m local_filesystem_service filesystem --static-dir /data/storage

# Custom gRPC port with filesystem backend
python -m local_filesystem_service --grpc-port 50052 filesystem --static-dir /data
```

### Environment Variables

All CLI options can also be set via environment variables:

- `FILESERVICE_STATIC_DIR`: Directory where files will be stored
- `FILESERVICE_SERVER_BASE_URI`: Base URI for the service (default: `file-storage://fileservice`)
- `FILESERVICE_TEST_FOLDER_MODE`: Folder simulation mode (default: `native`)
- `GRPC_SERVER_PORT`: Port for the gRPC server
- `HTTP_SERVER_PORT`: Port for the HTTP server
- `REDIRECT_HOST`: Host for redirect URLs
- `REDIRECT_PORT`: Port for redirect URLs

CLI options take precedence over environment variables.

### Testing with curl

Once the service is running locally, test it:

```bash
# Test REST API
curl http://localhost:8011/v1beta/capabilities/services

# View OpenAPI documentation for a specific endpoint
open http://localhost:8011/v1beta/fileobject/docs
# or for the filefolder API
open http://localhost:8011/v1beta/filefolder/docs

# Test file upload, size hint is a required parameter
curl -X PUT "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt?data_object_size=64" \
  -H "Content-Type: application/octet-stream" \
  -d "Hello World"

# Test file download
curl http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt
```

---

## Containerize

With the service validated locally, package it as a Docker image.

### Build the Wheel Package

Build the local filesystem service as a wheel from the `filesystem_example` directory:

```bash
# change to the directory to the filesystem example if you aren't already there
cd ./storage-api-1.0.0-beta/filesystem_example
# build the wheel package
./.poetry_venv/bin/poetry build
```

The wheel is created in `dist/`. Create a Dockerfile in the `filesystem_example` directory:

```bash
touch ./Dockerfile
```

### Dockerfile

```dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY ./dist /dist

RUN pip install /dist/omniverse_filesystem_storage_service-*-py3-none-any.whl

ENTRYPOINT ["local-filesystem-service"]
CMD []
```

### Build the Container

```bash
docker build -f ./Dockerfile -t storageapi_localfilesystem_service:local .
```

### Validate the Container

Create a host directory for storage data and mount it into the container:

```bash
# create a directory for the storage data
mkdir -p ~/storage-data
```

```bash
# validate the container was built and is available in the local registry
docker images | grep storageapi_localfilesystem_service
# run the container with ports exposed, mount a host storage directory, and set a custom storage directory inside the container
docker run -d -p 8011:8011 -p 50051:50051 \
  -v ~/storage-data:/data/storage \
  -e FILESERVICE_STATIC_DIR=/data/storage \
  --name localfilesystem-test \
  -t storageapi_localfilesystem_service:local
```

What each argument does:

- `-d`: Runs the container in the background (detached)
- `-p 8011:8011`: Maps the container REST/HTTP port 8011 to host port 8011
- `-p 50051:50051`: Maps the container gRPC port 50051 to host port 50051
- `-v ~/storage-data:/data/storage`: Mounts host directory into the container for persistent storage
- `-e FILESERVICE_STATIC_DIR=/data/storage`: Sets the storage directory inside the container
- `--name localfilesystem-test`: Assigns a name for easier management
- `-t storageapi_localfilesystem_service:local`: Specifies the image

Check the container is running:

```bash
docker ps | grep localfilesystem-test
```

### Test the Containerized Service

```bash
# Test REST API - check available services
curl http://localhost:8011/v1beta/capabilities/services

# You should also be able to read the written data from the previous testing
curl http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Ftest.txt
```

### View Container Logs

```bash
docker logs localfilesystem-test
```

Expected output:

```
2025-11-26 20:55:55,654 - INFO - gRPC Server launched on port 50051
2025-11-26 20:55:55,654 - INFO - Starting static server...
2025-11-26 20:55:55,668 - INFO - Started server process [1]
2025-11-26 20:55:55,668 - INFO - Waiting for application startup.
2025-11-26 20:55:55,668 - INFO - Application startup complete.
2025-11-26 20:55:55,668 - INFO - Uvicorn running on http://0.0.0.0:8011 (Press CTRL+C to quit)
```

### Clean Up the Test Container

```bash
docker stop localfilesystem-test
docker rm localfilesystem-test
```

---

## Deploy to Kubernetes

With the service containerized and tested in Docker, deploy it to your Kubernetes cluster. This section uses plain Kubernetes YAML manifests (namespace, PVC, Deployment, Service).

> **Note:** The commands below use `microk8s kubectl` as an example. On any other Kubernetes cluster, replace `microk8s kubectl` with `kubectl`.

### Create the Namespace

Choose a namespace for this deployment. Replace `<your-namespace>` in all commands and YAML below with your chosen namespace (e.g., `storage-apis-dev`, `omni-dev`, or whatever fits your environment):

```bash
# create the namespace
kubectl create namespace <your-namespace>

# validate the namespace was created
kubectl get namespaces | grep <your-namespace>
```

### Kubernetes Manifests

Create a file called `storage-service.yaml` and add resources step by step.

```bash
# open the file in your favorite text editor
code storage-service.yaml
```

#### PersistentVolumeClaim

The filesystem service uses local storage. Create a PVC to request storage from the cluster:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: storage-pvc  # Name of this PVC - referenced by the Deployment below
  namespace: <your-namespace>  # Must match the namespace above
spec:
  accessModes:
    - ReadWriteOnce  # Single node access mode
  resources:
    requests:
      storage: 10Gi  # Request 10GB of storage space
  # storageClassName: microk8s-hostpath  # Uncomment for MicroK8s; adjust for your cluster
```

Apply and verify:

```bash
kubectl apply -f storage-service.yaml
kubectl get pvc -n <your-namespace>
```

#### Deployment

Add the Deployment after the PVC, separated by `---`:

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: storage-service
  namespace: <your-namespace>
  labels:
    app: storage-service
spec:
  replicas: 1
  selector:
    matchLabels:
      app: storage-service
  template:
    metadata:
      labels:
        app: storage-service
    spec:
      containers:
      - name: storage
        image: storageapi_localfilesystem_service:local
        imagePullPolicy: Never  # Use local image, don't try to pull from registry
        ports:
        - containerPort: 8011  # HTTP/REST API port
          name: http
        - containerPort: 50051  # gRPC API port
          name: grpc
        env:
        - name: FILESERVICE_STATIC_DIR
          value: "/data/storage"
        - name: FILESERVICE_SERVER_BASE_URI
          value: "file-storage://fileservice"
        - name: FILESERVICE_TEST_FOLDER_MODE
          value: "native"
        - name: GRPC_SERVER_PORT
          value: "50051"
        - name: HTTP_SERVER_PORT
          value: "8011"
        - name: REDIRECT_HOST
          value: "http://localhost"
        - name: REDIRECT_PORT
          value: "8011"
        volumeMounts:
        - name: storage-data
          mountPath: /data/storage
      volumes:
      - name: storage-data
        persistentVolumeClaim:
          claimName: storage-pvc
```

Apply and wait for the pod:

```bash
kubectl apply -f storage-service.yaml
kubectl get pods -n <your-namespace> -w
```

Press `Ctrl+C` once the pod shows status `Running` and `1/1` ready.

#### Service

Add the Service after the Deployment, separated by `---`:

```yaml
---
apiVersion: v1
kind: Service
metadata:
  name: storage-service
  namespace: <your-namespace>
  labels:
    app: storage-service
spec:
  selector:
    app: storage-service
  ports:
  - name: http
    port: 8011
    targetPort: 8011
    protocol: TCP
  - name: grpc
    port: 50051
    targetPort: 50051
    protocol: TCP
  type: ClusterIP
```

Apply and verify:

```bash
kubectl apply -f storage-service.yaml
kubectl get endpoints -n <your-namespace> storage-service
```

You should see the pod IP and ports listed, confirming the Service can route traffic to your pods.

### Validate the Storage Service

Set up port-forwarding to test:

```bash
kubectl port-forward -n <your-namespace> service/storage-service 8011:8011
```

In another terminal:

```bash
# test writing to the storage service
curl -X PUT "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Fhello.txt?data_object_size=20" \
  -H "Content-Type: application/octet-stream" \
  --data "Hello from Storage API!"

# test reading from the storage service
curl http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Ffileservice%2Fhello.txt
```

Expected output:

```
>> "Hello from Storage API!"
```

---

## MicroK8s-Specific Steps

> **This section is optional.** Only follow these steps if you are using MicroK8s as your Kubernetes cluster. Skip this section entirely for EKS, AKS, GKE, or other clusters.

### Install and Configure MicroK8s

```bash
# install MicroK8s
sudo snap install microk8s --classic

# add the user to the microk8s group (avoids running as root)
sudo usermod -a -G microk8s $USER
# create the ~/.kube directory if it doesn't exist
mkdir -p ~/.kube
chmod 0700 ~/.kube
# re-enter the session to apply the changes
su - $USER
```

You can also install from the [MicroK8s website](https://microk8s.io/docs/install-alternatives).

### Enable Required Add-ons

```bash
# make sure microk8s is running
microk8s.start
# enable the registry for local docker images
microk8s enable registry
# enable DNS for service discovery
microk8s enable dns
# enable ingress controller for external access
microk8s enable ingress
# enable storage for persistent volumes on the localhost filesystem
microk8s enable hostpath-storage

microk8s status --wait-ready
```

Validate the status:

```bash
microk8s kubectl get nodes
microk8s kubectl get pods --all-namespaces
```

### Import the Docker Image into MicroK8s

Push the Docker image into the MicroK8s registry:

```bash
# save and import the newly built container
docker save storageapi_localfilesystem_service:local -o storageapi_localfilesystem_service.tar
microk8s ctr image import ./storageapi_localfilesystem_service.tar

# validate the container was imported
microk8s ctr image ls | grep storageapi_localfilesystem_service
```

### MicroK8s PVC Storage Class

When using MicroK8s, set the `storageClassName` in your PVC to `microk8s-hostpath`:

```yaml
storageClassName: microk8s-hostpath
```

You can inspect the storage mount path on the host:

```bash
# default mount path for microk8s hostpath storage
cd /var/snap/microk8s/common/default-storage/

# storage path (replace {pvc-uuid} with your PVC UUID)
cd <your-namespace>/storage-pvc-{pvc-uuid}/

# you should see the files written by the storage service
ls -lR
```

> **Note:** With MicroK8s, prefix all `kubectl` and `helm` commands with `microk8s`. For example: `microk8s kubectl get pods -n <your-namespace>` and `microk8s helm install ...`.

---

## Add Discovery Service

The Discovery Service defines the services in your deployment and exposes a single endpoint. Clients request `{hostname}:{port}/api/v1/services` and receive a JSON object with service information.

### Pull the Helm Chart

Pull the Discovery Service Helm chart from NGC:

```bash
# pull the chart from NGC
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/discovery-service-2.3.8.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

# unpack the chart and cd into the directory
tar -xvf discovery-service-2.3.2.tgz
cd discovery-service
```

### Create the NGC Pull Secret

Create a pull secret so the cluster can pull images from the registry:

```bash
# create a Kubernetes secret with the pull secret
kubectl create secret docker-registry ngcpull-secret --docker-server=nvcr.io --docker-username='$oauthtoken' --docker-password=${NGC_API_KEY} -n <your-namespace>

# validate the secret was created
kubectl get secret ngcpull-secret -n <your-namespace>
```

### Configure discovery-values.yaml

Create `discovery-values.yaml` to override values for the Discovery Service:

```bash
code discovery-values.yaml
```

Reference the pull secret. The Discovery Service image is pulled from `nvcr.io/nvidia/omniverse/` — the chart defaults to this registry, so you only need to override `image.repository` if you're using a private registry mirror. Always include the pull secret:

```yaml
image:
  # repository defaults to nvcr.io/nvidia/omniverse/simple-nginx (NGC production registry)
  # Only override this if pulling from a private registry mirror:
  # repository: "your-private-registry.example.com/omniverse/simple-nginx"
  pullSecrets:
    - name: ngcpull-secret
```

### Discovery Schema

The Discovery Service responds with a JSON object describing each service. The schema:

```json
{
    "schema-version": 1,
    "services": [
        {
            "id": "service-service-id...",
            "name": "service-name",
            "type": "service-type",
            "rest": "https://{service-hostname}:{service-port}",
            "grpc": "grpc://{service-hostname}:{service-port}"
        }
    ]
}
```

Schema fields (used by Kit-based apps to discover services):

- `id`: Unique identifier for the service
- `name`: Human-readable name
- `type`: Service type (e.g., `storage`)
- `rest`: REST endpoint (use `http` prefix for non-TLS). Optional; only for REST clients
- `grpc`: gRPC endpoint (use `http` prefix for non-TLS). Optional; only for gRPC clients

### Set the Discovery Response

Configure the Discovery Service to include the storage service. The fully qualified hostname is built at deploy time from the host, namespace, and port:

- **tls**: `true` produces `https`, `false` produces `http`
- **host**: Service name (e.g. `storage-service`). An empty string `""` auto-populates with the cluster-internal FQDN
- **port**: Service port

Example: in namespace `<your-namespace>`, the storage service is `http://storage-service.<your-namespace>.svc.cluster.local` with the configured ports.

**For cluster-internal use** (empty host auto-populates):

```yaml
image:
  # repository: nvcr.io/nvidia/omniverse/simple-nginx  (default — only override for private registries)
  pullSecrets:
    - name: ngcpull-secret

discovery:
  services:
    - id: "storage-service-01"
      name: "Storage Service"
      type: "storage"
      endpoints:
        grpc:
          host: ""
          port: 8011
          path: "/"
          tls: false
        rest:
          host: ""
          port: 8012
          path: "/"
          tls: false
```

**For localhost port-forwarding** (explicit localhost host):

```yaml
image:
  # repository: nvcr.io/nvidia/omniverse/simple-nginx  (default — only override for private registries)
  pullSecrets:
    - name: ngcpull-secret

discovery:
  services:
    - id: "storage-service-01"
      name: "Storage service"
      type: "storage"
      endpoints:
        grpc:
          host: "localhost"
          port: 8012
          path: "/"
          tls: false
        rest:
          host: "localhost"
          port: 8011
          path: "/"
          tls: false
```

### Install the Discovery Service

```bash
# validate the chart
helm template . -f discovery-values.yaml

# dry-run the install
helm upgrade --install discovery-service . -f discovery-values.yaml --namespace <your-namespace> --dry-run --debug

# install the discovery service
helm upgrade --install discovery-service . -f discovery-values.yaml --namespace <your-namespace>

# validate the pod is running (may take a few minutes)
kubectl get pods -n <your-namespace>
```

### Validate the Discovery Service

Use port-forwarding to test:

```bash
# set up port forwarding
kubectl port-forward -n <your-namespace> service/discovery-service 8080:8080

# test the discovery service
curl http://localhost:8080/api/v1/services
```

You should see a JSON response listing the services in the deployment.

---

## Access from Localhost

To make both services accessible from your host machine, use `kubectl port-forward` in three separate terminal sessions:

```bash
# Terminal 1: port forward the discovery service
kubectl port-forward -n <your-namespace> service/discovery-service 8080:8080

# Terminal 2: port forward the storage service REST endpoint
kubectl port-forward -n <your-namespace> service/storage-service 8011:8011

# Terminal 3: port forward the storage service gRPC endpoint (maps host 8012 to container 50051)
kubectl port-forward -n <your-namespace> service/storage-service 8012:50051
```

### Verify External Access

Test the Discovery Service:

```bash
curl http://localhost:8080/api/v1/services
```

Expected response:

```json
{
    "schema-version": 1,
    "services": [
        {
            "id": "storage-service-01",
            "name": "Storage service",
            "type": "storage",
            "grpc": "grpc://localhost:8012",
            "rest": "http://localhost:8011"
        }
    ]
}
```

Test the Storage Service:

```bash
# Test writing to the storage service
curl -X PUT "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Fstorage-service%2Fhello.txt?data_object_size=20" \
  -H "Content-Type: application/octet-stream" \
  --data "Hello from Storage API via localhost!"

# Test reading from the storage service
curl http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Fstorage-service%2Fhello.txt
```

Expected output:

```
>> "Hello from Storage API via localhost!"
```

### End-to-End Validation

Verify the complete workflow: query Discovery to get the Storage Service URL, then use that URL:

```bash
# Step 1: Query Discovery Service
DISCOVERY_RESPONSE=$(curl -s http://localhost:8080/api/v1/services)
echo "$DISCOVERY_RESPONSE"

# Step 2: Extract Storage Service URL using jq
STORAGE_URL=$(echo "$DISCOVERY_RESPONSE" | jq -r '.services[] | select(.type == "storage") | .rest')
echo "Storage service REST URL: $STORAGE_URL"

# Step 3: Use the Storage Service URL from Discovery response
curl "${STORAGE_URL}/v1beta/fileobject/by-address/file-storage%3A%2F%2Fstorage-service%2Fhello.txt"
```

This demonstrates the complete workflow: external client -> Discovery Service -> Storage Service.

---

## Kit SDK Testing

### Download and Configure Kit

1. **Download Kit 109.0.1 SDK or later** from NGC:
   - [Linux](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/kit-sdk-linux)
   - [Windows](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/kit-sdk-windows)

2. **Extract and prepare the SDK:**

   ```bash
   cd kit-sdk-linux-109.0.1
   ```

3. **Configure Kit for your deployment.** Edit the shell launch script (e.g., `omni.app.full.sh`) and insert before the `${EXEC:-exec}` line:

   ```bash
   # for local deployment or deployments that do not use secure connections use http:// instead of https://
   export OMNI_STORAGE_DISCOVERY=http://{discovery-url}
   ```

   For a local port-forwarded deployment, this would be:

   ```bash
   export OMNI_STORAGE_DISCOVERY=http://localhost:8080
   ```

4. **Launch Kit:**

   ```bash
   ./omni.app.full.sh
   ```

### Upload a Test USD File

First, upload a simple USDA file to the storage service. Save the following as `cube.usda`:

```usda
#usda 1.0
(
   customLayerData = {
      dictionary cameraSettings = {
            dictionary Front = {
               double3 position = (0, 0, 50000)
               double radius = 500
            }
            dictionary Perspective = {
               double3 position = (31.228726468341044, 6.955740397133659, 15.62341018564353)
               double3 target = (0.06364292377851655, 3.4744941220079357, -0.9826701764198784)
            }
            string boundCamera = "/OmniverseKit_Persp"
      }
   }
)

def Xform "World"
{
   def Cube "Cube"
   {
   }

   def SphereLight "KeyLight"
   {
      float inputs:intensity = 10000
      double3 xformOp:scale = (8, 8, 8)
      double3 xformOp:translate = (10, 10, 0)
      uniform token[] xformOpOrder = ["xformOp:translate", "xformOp:scale"]
   }
}
```

Upload the file:

```bash
# generate the USD data
export USD_DATA="$(cat cube.usda)"
# get the data size
export SIZE="$(echo -n "${USD_DATA}" | wc -c)"

# upload the usda file to the storage service
curl -X PUT "http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Fstorage-service%2Fcube.usda?data_object_size=${SIZE}&upload_preference=body" -H "Content-Type: application/json" --data "${USD_DATA}"
```

Validate the upload:

```bash
# list the top level of the storage service
curl "http://localhost:8011/v1alpha/filefolder/list/file-storage%3A%2F%2Fstorage-service"
```

### Open the USD File in Kit

1. **File > Open** -- Due to a known issue in Kit 109.0.1, you cannot add the connection to the Content Browser. Use File > Open instead.
2. **Enter the storage URL** -- Use the file path without percent encoding: `file-storage://storage-service/cube.usda`
3. **View the scene** -- After the file opens, you should see a rendered cube with lighting.

---

## Ingress (Optional)

Setting up ingress removes the need for `kubectl port-forward`. This section covers MicroK8s NGINX ingress for the Example Adapter Stack.

### Enable NGINX Ingress

```bash
microk8s enable ingress
```

> **Note:** The ingress class name varies by MicroK8s version. Check which class is available on your cluster:
>
> ```bash
> microk8s kubectl get ingressclass
> ```
>
> It may be `nginx` or `public`. Use the correct class name in the `ingressClassName` field below.

### Port Reference

| Adapter | gRPC port | REST port |
|---------|-----------|-----------|
| Python filesystem example | 50051 | 8011 |

### Two Ingress Mechanisms

This stack requires two ingress mechanisms:

1. **HTTP ingress** for the Discovery Service (standard HTTP routing)
2. **TCP pass-through** for the Storage Service (gRPC and REST on non-standard ports)

### HTTP Ingress for Discovery

Choose one of the following options.

#### Option A: Hostname-Based (Requires /etc/hosts Entry)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: discovery-ingress
  namespace: <your-namespace>
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  ingressClassName: public
  rules:
  - host: discovery.local
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: discovery-service
            port:
              number: 8080
```

Access via: `http://discovery.local/api/v1/services`

#### Option B: Direct IP (No Hostname Needed)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: discovery-ingress
  namespace: <your-namespace>
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
spec:
  ingressClassName: public
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: discovery-service
            port:
              number: 8080
```

Access via: `http://127.0.0.1/api/v1/services`

### TCP Pass-Through for Storage

The Storage Service uses gRPC (port 50051) and REST (port 8011), which require TCP pass-through rather than HTTP ingress.

#### Step 1: Create the TCP ConfigMap

Create a ConfigMap that maps external ports to your storage service:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: nginx-ingress-tcp-microk8s-conf
  namespace: ingress
data:
  "8011": "<your-namespace>/storage-service:8011"
  "50051": "<your-namespace>/storage-service:50051"
```

Apply it:

```bash
kubectl apply -f tcp-configmap.yaml
```

#### Step 2: Patch the DaemonSet Ports

Patch the ingress controller DaemonSet to expose the TCP ports. Use a strategic merge patch:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nginx-ingress-microk8s-controller
  namespace: ingress
spec:
  template:
    spec:
      containers:
      - name: nginx-ingress-microk8s
        ports:
        - containerPort: 8011
          hostPort: 8011
          protocol: TCP
        - containerPort: 50051
          hostPort: 50051
          protocol: TCP
```

Apply the ports patch:

```bash
kubectl patch daemonset nginx-ingress-microk8s-controller -n ingress --type strategic --patch-file daemonset-ports-patch.yaml
```

#### Step 3: Patch the DaemonSet Args

The ingress controller needs the `--tcp-services-configmap` argument. First, read the existing args:

```bash
kubectl get daemonset nginx-ingress-microk8s-controller -n ingress \
  -o jsonpath='{.spec.template.spec.containers[0].args}' | jq .
```

Then create an args patch that includes the full existing args list plus the TCP ConfigMap reference:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nginx-ingress-microk8s-controller
  namespace: ingress
spec:
  template:
    spec:
      containers:
      - name: nginx-ingress-microk8s
        args:
          # Include all existing args from the output above, then add:
          - --tcp-services-configmap=ingress/nginx-ingress-tcp-microk8s-conf
```

Apply the args patch:

```bash
kubectl patch daemonset nginx-ingress-microk8s-controller -n ingress --type strategic --patch-file daemonset-args-patch.yaml
```

> **Note:** The DaemonSet name (`nginx-ingress-microk8s-controller`) and container name (`nginx-ingress-microk8s`) may vary depending on your MicroK8s version. Check with:
>
> ```bash
> kubectl get daemonset -n ingress
> kubectl get daemonset <daemonset-name> -n ingress -o jsonpath='{.spec.template.spec.containers[0].name}'
> ```

### /etc/hosts Entry

Add the following entry to `/etc/hosts` so hostnames resolve to localhost:

```
127.0.0.1  discovery.local storage.local
```

### Update Discovery Values for Ingress

Update `discovery-values.yaml` to use the ingress hostnames instead of localhost port-forwarding:

```yaml
discovery:
  services:
    - id: "storage-service-01"
      name: "Storage Service"
      type: "storage"
      endpoints:
        grpc:
          host: "storage.local"
          port: 50051
          path: "/"
          tls: false
        rest:
          host: "storage.local"
          port: 8011
          path: "/"
          tls: false
```

### Upgrade Discovery and Validate

```bash
# upgrade Discovery with the new values
helm upgrade discovery-service . -f discovery-values.yaml --namespace <your-namespace>

# validate the Discovery Service via ingress
curl http://discovery.local/api/v1/services

# validate the Storage Service via ingress
curl http://storage.local:8011/v1beta/capabilities/services
```

---

## Troubleshooting

If localhost access stops working after port-forwarding, try these checks in order:

1. **Pods healthy:**

   ```bash
   kubectl get pods -n <your-namespace>
   kubectl describe pod -n <your-namespace> -l app=storage-service
   kubectl describe pod -n <your-namespace> -l app=discovery-service
   ```

2. **Services and endpoints wired up:**

   ```bash
   kubectl get svc,endpoints -n <your-namespace>
   ```

3. **Port-forward sessions still running:**

   ```bash
   ps -ef | grep "kubectl port-forward" | grep -E "storage-service|discovery-service" || true
   # If they are not running, rerun the port-forward commands from above.
   ```

4. **Curl with verbose output:**

   ```bash
   curl -v http://localhost:8080/api/v1/services
   curl -v http://localhost:8011/v1beta/fileobject/by-address/file-storage%3A%2F%2Fstorage-service%2Fhello.txt
   ```

5. **Inspect logs:**

   ```bash
   kubectl logs deployment/discovery-service -n <your-namespace>
   kubectl logs deployment/storage-service -n <your-namespace>
   ```

6. **TLS certificate mismatch (MicroK8s-specific):**
   If you see x509 certificate errors with MicroK8s port-forwarding:

   ```bash
   sudo microk8s refresh-certs --cert server.crt
   sudo microk8s stop && sudo microk8s start
   ```

7. **Port already in use:**
   Find and kill the process using the port, or forward to a different available port:

   ```bash
   ss -tlnp | grep {port}
   kill -9 {pid}
   ```

---

## Cleanup

To clean up the entire deployment, delete the namespace:

```bash
kubectl delete namespace <your-namespace>
```

This removes all resources (Storage Service, Discovery Service, ConfigMaps, PVCs, Secrets, etc.).

To also uninstall the Discovery Helm release explicitly before deleting the namespace:

```bash
helm uninstall discovery-service -n <your-namespace>
kubectl delete namespace <your-namespace>
```

---

## Next Steps

- **Production adapter stack:** Deploy the NVIDIA production adapter with full services -- see `references/deployment/production-adapter-stack.md`
- **Custom adapter development:** Build your own storage service adapter -- see `references/development/`
