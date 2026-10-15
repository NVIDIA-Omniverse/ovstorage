# Production Adapter Stack

## Overview

The Production Adapter Stack uses the NVIDIA pre-built Storage Service adapter (S3 and Azure Blob Storage) with a composable set of services. The stack is **cluster-agnostic** -- any Kubernetes distribution (EKS, AKS, GKE, on-prem, etc.) works.

**Minimum starting point:** Storage Service + Discovery Service. From there, add services incrementally as your needs require:

| Layer | Services | Required? |
|-------|----------|-----------|
| Core | Storage Service, Discovery Service | Yes |
| Notifications | RabbitMQ, Event Aggregation, Event Consumer | Optional |
| Ingress | Contour (load balancer) | Optional |
| Authentication | Envoy Auth Extension (OIDC) | Optional |
| UI | Storage Navigator | Optional |

Each optional service is independently deployable. You do not need to deploy all services -- add them as your requirements grow.

### v1.0.0 Release Versions

The chart and image versions below are for the **v1.0.0 GA release**. Update these when a new release is available.

| Service | Helm Chart | Chart Version | Container Image | Image Tag |
|---------|-----------|---------------|-----------------|-----------|
| Storage Service | `storage-service` | 1.0.2 | `storage-service` | 1.0.2 |
| Discovery Service | `discovery-service` | 2.3.8 | `simple-nginx` | 0.2.6 |
| Event Aggregation | `event-aggregation-service` | 1.5.52 | `event-aggregation-service` | 1.5.52 |
| Event Consumer | `event-consumer-service` | 1.9.6 | `event-consumer-service` | 1.9.6 |
| RabbitMQ | `rabbitmq` | 99.3.0 | `rabbitmq` | 4.1.3-debian-12-r1 |
| Envoy Auth Extension | `envoy-auth-extension` | 2.3.3 | `envoy-auth-ext` | 2.3.3 |
| Storage Navigator | `storage-navigator` | 1.0.1 | `storage-navigator` | 1.0.1 |
| Integration Tests | `storage-api-integration-tests` | 1.0.3 | `integration-tests` | 1.0.3 |

---

## Prerequisites

### Minimum Application Versions

- **Kubernetes** -- v1.31.0+
- **kubectl** -- v1.32.0+
- **Helm** -- v3.0.0+

### NGC Account

Create an NGC account at https://ngc.nvidia.com/signin. Generate an API key with **NGC Catalog** and **NVIDIA Private Registry** permissions.

### Recommended Hardware

Compute nodes are sufficient (no GPUs required).

- **CPU**: 32 vCPU
- **Memory**: 128 GiB
- Instance examples:
  - AWS: m5.8xlarge (32 vCPU, 128 GiB)
  - Azure: Standard_D32as_v4 (32 vCPU, 128 GiB)

### Namespace and Pull Secret

```bash
# create the namespace
kubectl create namespace storage-apis

# create the image-pull secret (replace ${NGC_API_KEY} with your key starting with nvapi-)
kubectl create secret docker-registry ngcpull-secret \
  --docker-server "nvcr.io" \
  --docker-username '$oauthtoken' \
  --docker-password '${NGC_API_KEY}' \
  -n storage-apis

# validate
kubectl get secret ngcpull-secret -n storage-apis
```

---

## Storage Service

The Storage Service is the core component that provides S3 and Azure Blob Storage access via gRPC (port 8011) and REST (port 8012).

### Choose Your Storage Backend

The Storage Service supports **S3** and **Azure Blob Storage** backends (public or private). S3-compatible storage (e.g., MinIO) is also supported via custom endpoints. Set up at least one backend before deploying.

### AWS S3 Bucket Permissions

Attach the following minimal IAM policy to the bucket or the IAM user/role accessing it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BucketLevelPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Resource": "arn:aws:s3:::BUCKET_NAME_HERE"
    },
    {
      "Sid": "ObjectLevelPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::BUCKET_NAME_HERE/*"
    }
  ]
}
```

Replace `BUCKET_NAME_HERE` with your actual S3 bucket name in both Resource ARNs. The versioning-related permissions (`s3:ListBucketVersions`, `s3:GetObjectVersion`, `s3:DeleteObjectVersion`) are optional if you do not use versioned buckets.

### Azure Blob Storage Permissions

Assign the **Storage Blob Data Contributor** role (recommended) to the identity used by the Storage Service:

```bash
az role assignment create \
  --role "Storage Blob Data Contributor" \
  --assignee <service-principal-id> \
  --scope /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>/blobServices/default/containers/<container-name>
```

Alternatively, for minimal permissions, create a custom role definition:

```json
{
  "Name": "Omniverse Storage Blob Operator",
  "IsCustom": true,
  "Description": "Minimal permissions for the Omniverse Storage Service to read/write Azure Blob Storage.",
  "Actions": [],
  "NotActions": [],
  "DataActions": [
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/move/action",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read",
    "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write"
  ],
  "NotDataActions": [],
  "AssignableScopes": [
    "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>"
  ]
}
```

Create and assign the custom role:

```bash
az role definition create --role-definition custom-role.json
az role assignment create \
  --role "Omniverse Storage Blob Operator" \
  --assignee <service-principal-id> \
  --scope /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>/blobServices/default/containers/<container-name>
```

### Pull the Storage Service Helm Chart

```bash
# pull the chart from NGC
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/storage-service-1.0.2.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

# unpack the chart
tar -xvf storage-service-0.7.19.tgz
cd storage-service
```

### Configure storage-values.yaml

#### Base Values

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
```

#### Private S3 Bucket Configuration

Create a Kubernetes secret for your S3 credentials. Replace `{mybucketname}` with your bucket name and provide your access keys:

```bash
kubectl create secret generic {mybucketname}-bucket-secret \
  --from-literal=BUCKET_ACCESS_KEY_ID={BUCKET_ACCESS_KEY_ID} \
  --from-literal=BUCKET_SECRET_ACCESS_KEY={BUCKET_SECRET_ACCESS_KEY} \
  --namespace storage-apis

# validate
kubectl get secret {mybucketname}-bucket-secret -n storage-apis
```

Add the S3 endpoint configuration to `storage-values.yaml`:

```yaml
config:
  storage:
    s3:
      endpoints:
        "{mybucketname}.s3.{region}.amazonaws.com":
          credentials:
            accessKey:
              accessKeyId: "${BUCKET_ACCESS_KEY_ID}"
              secretAccessKey: "${BUCKET_SECRET_ACCESS_KEY}"
```

Add `extraEnvs` to inject the secret values as environment variables:

```yaml
extraEnvs:
  - name: BUCKET_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: {mybucketname}-bucket-secret
        key: BUCKET_ACCESS_KEY_ID
  - name: BUCKET_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: {mybucketname}-bucket-secret
        key: BUCKET_SECRET_ACCESS_KEY
```

#### Azure Private Blob Storage Configuration

Create a Kubernetes secret for your Azure credentials:

```bash
kubectl create secret generic {mystorageaccount}-container-secret \
  --from-literal=AZ_BLOB_STORAGE_KEY={AZ_BLOB_STORAGE_KEY} \
  --namespace storage-apis

# validate
kubectl get secret {mystorageaccount}-container-secret -n storage-apis
```

Add the Azure endpoint configuration to `storage-values.yaml`:

```yaml
config:
  storage:
    azure:
      azureBlob:
        endpoints:
          {mystorageaccount}.blob.core.windows.net:
            credentials:
              storageAccount:
                storageAccount: {mystorageaccount}
                storageKey: "${AZ_BLOB_STORAGE_KEY}"
```

Add `extraEnvs` to inject the secret value:

```yaml
extraEnvs:
  - name: AZ_BLOB_STORAGE_KEY
    valueFrom:
      secretKeyRef:
        name: {mystorageaccount}-container-secret
        key: AZ_BLOB_STORAGE_KEY
```

#### Notification Integration Values (Optional)

If you deploy the Notifications Services, add the following to `storage-values.yaml`. Create a secret first:

```bash
kubectl create secret generic storage-notifications-secret \
  --from-literal=AZURE_SERVICE_BUS_POLICY_KEY="<service-bus-policy-key>" \
  --from-literal=SQS_ACCESS_KEY_ID="<aws-access-key-id>" \
  --from-literal=SQS_SECRET_ACCESS_KEY="<aws-secret-access-key>" \
  --from-literal=NOTIFICATION_SERVICE_CLIENT_SECRET="<client-secret>" \
  --namespace storage-apis
```

> When using IRSA for SQS, omit `SQS_ACCESS_KEY_ID` and `SQS_SECRET_ACCESS_KEY` from both the secret and `extraEnvs`.

Add notification `extraEnvs` (append to existing `extraEnvs` list):

```yaml
extraEnvs:
  # ... existing bucket credential envs ...
  - name: AZURE_SERVICE_BUS_POLICY_KEY
    valueFrom:
      secretKeyRef:
        name: storage-notifications-secret
        key: AZURE_SERVICE_BUS_POLICY_KEY
  - name: SQS_ACCESS_KEY_ID
    valueFrom:
      secretKeyRef:
        name: storage-notifications-secret
        key: SQS_ACCESS_KEY_ID
  - name: SQS_SECRET_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: storage-notifications-secret
        key: SQS_SECRET_ACCESS_KEY
  - name: NOTIFICATION_SERVICE_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: storage-notifications-secret
        key: NOTIFICATION_SERVICE_CLIENT_SECRET
```

Add the storage events and notification client config:

```yaml
config:
  # ... existing storage config ...
  storageEvents:
    azureServiceBus:
      enabled: true
      queueNamespace: "<service-bus-namespace-name>"
      queueName: "<service-bus-queue-name>"
      credentials:
        sharedAccessPolicyKey:
          policyName: "RootManageSharedAccessKey"
          policyKey: "${AZURE_SERVICE_BUS_POLICY_KEY}"

    sqs:
      enabled: true
      queueUrl: "<sqs-queue-url>"
      region: "<aws-region>"
      # When using IRSA/service account, omit the credentials block entirely
      credentials:
        accessKey:
          accessKeyId: "${SQS_ACCESS_KEY_ID}"
          secretAccessKey: "${SQS_SECRET_ACCESS_KEY}"

  notificationClient:
    enabled: true
    endpointUrl: "http://event-aggregation-service.storage-apis.svc.cluster.local:50051"
    secure: false
```

### Install the Storage Service

```bash
# validate the chart
helm template . -f storage-values.yaml

# dry-run
helm upgrade --install storage-service . -f storage-values.yaml --namespace storage-apis --dry-run --debug

# install
helm upgrade --install storage-service . -f storage-values.yaml --namespace storage-apis

# wait for pods
kubectl get pods -n storage-apis
```

### Validate the Storage Service

```bash
# test REST endpoint
curl http://storage-service.storage-apis.svc.cluster.local:8012/v1alpha/capabilities/services

# test access to a public S3 bucket
curl -v "http://storage-service.storage-apis.svc.cluster.local:8012/v1alpha/filefolder/list/https%3A%2F%2Fomniverse-content-production.s3.us-west-2.amazonaws.com%2F"
```

Using port-forwarding for local testing:

```bash
kubectl port-forward -n storage-apis service/storage-service 8012:8012

curl http://localhost:8012/v1alpha/capabilities/services
```

---

## Discovery Service

The Discovery Service provides a single JSON endpoint so clients can find and connect to all services. Clients request one JSON response that lists all available services and endpoints.

### Pull the Discovery Service Helm Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/discovery-service-2.3.8.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf discovery-service-2.3.2.tgz
cd discovery-service
```

### Configure discovery-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
  # repository and tag default to the chart's appVersion — only override for private registries
  # repository: "nvcr.io/nvidia/omniverse/simple-nginx"
  # tag: "0.2.6"
```

### Discovery Schema

The Discovery Service responds with JSON describing each service:

```json
{
    "schema-version": 1,
    "services": [
        {
            "id": "service-id",
            "name": "service-name",
            "type": "service-type",
            "rest": "https://{service-hostname}:{service-port}",
            "grpc": "grpc://{service-hostname}:{service-port}"
        }
    ]
}
```

Schema fields:
- `id` -- Unique identifier for the service
- `name` -- Human-readable name
- `type` -- Service type (e.g., `storage`, `event-aggregation`, `event-consumer`)
- `rest` -- REST endpoint (use `http` prefix for non-TLS). Optional.
- `grpc` -- gRPC endpoint (use `http` prefix for non-TLS). Optional.

### Set the Discovery Response

Configure `discovery.services[]` in `discovery-values.yaml`. When `host` is left empty, it is automatically populated at deploy time with the default service name.

Example in namespace `storage-apis`: the storage service resolves to `http://storage-service.storage-apis.svc.cluster.local` with gRPC on 8011 and REST on 8012.

```yaml
discovery:
  services:
    - id: "storage-service-01"
      name: "Storage Service"
      type: "storage"
      endpoints:
        grpc:
          host: ""   # empty = auto-populated with default service name at deploy time
          port: 8011
          path: ""
          tls: false
        rest:
          host: ""   # empty = auto-populated with default service name at deploy time
          port: 8012
          path: ""
          tls: false
```

### Install the Discovery Service

```bash
# validate
helm template . -f discovery-values.yaml

# dry-run
helm upgrade --install discovery-service . -f discovery-values.yaml --namespace storage-apis --dry-run --debug

# install
helm upgrade --install discovery-service . -f discovery-values.yaml --namespace storage-apis

# wait for pods
kubectl get pods -n storage-apis
```

### Validate the Discovery Service

```bash
curl http://discovery-service.storage-apis.svc.cluster.local:8080/api/v1/services
```

---

## Notifications Services (Optional)

Enable when you need event-driven workflows (e.g., Kit-based apps reacting to file create/delete/modify events). If you do not need notifications, skip this section.

The notification stack consists of three components:
1. **RabbitMQ** -- event broker
2. **Event Aggregation Service** -- publishes events to RabbitMQ
3. **Event Consumer Service** -- clients consume events from RabbitMQ

### RabbitMQ

#### Pull the RabbitMQ Helm Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/rabbitmq-99.3.0.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf rabbitmq-99.3.0.tgz
cd rabbitmq
```

#### Create RabbitMQ Secrets

```bash
# RabbitMQ password secret
kubectl create secret generic rabbitmq-service-env \
  --from-literal=rabbitmq-password={RABBITMQ_PASSWORD} \
  --namespace storage-apis

# RabbitMQ connection URI for event services (note the /notifications vhost path)
kubectl create secret generic event-services-env \
  --from-literal=rabbitmq_uri=amqp://rabbitmq-user:{RABBITMQ_PASSWORD}@rabbitmq:5672/notifications \
  --namespace storage-apis
```

#### Configure rabbitmq-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
  registry: nvcr.io
  repositoryPrefix: nvidia/omniverse
  repository: rabbitmq
  tag: 4.1.3-debian-12-r1

auth:
  username: rabbitmq-user
  existingPasswordSecret: "rabbitmq-service-env"
  existingSecretPasswordKey: "rabbitmq-password"

persistence:
  enabled: false

# Load vhost definitions on startup
loadDefinition:
  enabled: true
  existingSecret: rabbitmq-load-definition
extraSecrets:
  rabbitmq-load-definition:
    load_definition.json: |
      {
        "vhosts": [
          {"name": "/"},
          {"name": "notifications"}
        ]
      }
initScripts:
  setup-permissions.sh: |
    #!/bin/bash
    rabbitmqctl set_permissions -p notifications rabbitmq-user ".*" ".*" ".*"
```

#### Deploy RabbitMQ

```bash
helm upgrade --install rabbitmq -n storage-apis -f rabbitmq-values.yaml .

# validate
kubectl get pods -n storage-apis
kubectl get service -n storage-apis
```

### Event Aggregation Service

#### Pull the Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/event-aggregation-service-1.5.52.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf event-aggregation-service-1.4.13.tgz
cd event-aggregation-service
```

#### Configure event-aggregation-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret

# Override the default secret name to use our shared secret
envSecretName: event-services-env
```

#### Deploy

```bash
helm upgrade --install event-aggregation-service -n storage-apis -f event-aggregation-values.yaml .

# validate
kubectl get pods -n storage-apis
kubectl get service -n storage-apis
```

### Event Consumer Service

#### Pull the Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/event-consumer-service-1.9.6.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf event-consumer-service-1.7.16.tgz
cd event-consumer-service
```

#### Configure event-consumer-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret

# Override the default secret name to use our shared secret
envSecretName: event-services-env
```

#### Deploy

```bash
helm upgrade --install event-consumer-service -n storage-apis -f event-consumer-values.yaml .

# validate
kubectl get pods -n storage-apis
kubectl get service -n storage-apis
```

### SQS IAM Policy for Notifications

If the Storage Service uses a separate IAM user for SQS (not IRSA), create this policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StorageServiceSQSAccess",
      "Effect": "Allow",
      "Action": [
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes",
        "sqs:GetQueueUrl"
      ],
      "Resource": "arn:aws:sqs:<aws-region>:<aws-account-id>:<sqs-queue-name>"
    }
  ]
}
```

When using IRSA, attach this policy to the same IAM role used for S3 bucket access -- no separate user or access keys needed.

### SQS Queue Policy

The SQS queue must allow S3 to send notification messages. Apply this queue policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ToSendMessage",
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:<aws-region>:<aws-account-id>:<sqs-queue-name>",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:s3:::BUCKET_NAME_HERE"
        }
      }
    }
  ]
}
```

### Multi-Region Notifications: SNS -> SQS Fan-Out

For multi-region deployments where multiple S3 buckets in different regions need to publish to a single SQS queue, use an SNS topic as an intermediary:

1. **Create an SNS topic** in the same region as your SQS queue.

2. **SNS topic policy** — allow S3 buckets from any region to publish:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ToPublish",
      "Effect": "Allow",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:<aws-region>:<aws-account-id>:<sns-topic-name>",
      "Condition": {
        "ArnLike": {
          "aws:SourceArn": "arn:aws:s3:::*"
        }
      }
    }
  ]
}
```

3. **Subscribe the SQS queue to the SNS topic** with a filter policy to only receive storage events:

```json
{
  "s3:EventName": [
    { "prefix": "s3:ObjectCreated:" },
    { "prefix": "s3:ObjectRemoved:" }
  ]
}
```

4. **SQS queue policy for SNS** — allow the SNS topic to send messages to the queue:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSNSToSendMessage",
      "Effect": "Allow",
      "Principal": {
        "Service": "sns.amazonaws.com"
      },
      "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:<aws-region>:<aws-account-id>:<sqs-queue-name>",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:sns:<aws-region>:<aws-account-id>:<sns-topic-name>"
        }
      }
    }
  ]
}
```

5. **Configure each S3 bucket** to send event notifications to the SNS topic (instead of directly to SQS).

### Azure Service Bus Configuration

1. Create or select a Service Bus Namespace (Basic tier is sufficient) in the same region as your other services.
2. Create a queue in the namespace. Set message time to live (e.g., several hours).
3. In the Storage Account, go to **Events** and create an event subscription:
   - Event Schema: **Cloud Event Schema v1.0**
   - Event Types: **Blob Created** and **Blob Deleted**
   - Endpoint Type: **Service Bus Queue**, pointing to the queue from step 2.

### Redeploy Storage Service with Notifications

After configuring the notification values in `storage-values.yaml` (see Storage Service section above), redeploy:

```bash
helm upgrade --install storage-service ./storage-service -f ./storage-service/storage-values.yaml --namespace storage-apis
```

---

## Ingress (Optional)

Use **Contour** as the load balancer for external access.

### Install Contour

```bash
helm repo add contour https://projectcontour.github.io/helm-charts/
helm pull contour/contour --version 0.2.0

# deploy (optionally add -f local-contour-values.yaml for CSP-specific config)
helm upgrade --install --create-namespace -n contour-system contour contour-0.2.0.tgz

# verify
kubectl get pods -n contour-system
```

#### AWS NLB Annotations Example

If deploying on AWS with a Network Load Balancer, create a `local-contour-values.yaml`:

```yaml
envoy:
    service:
        annotations:
          service.beta.kubernetes.io/aws-load-balancer-type: nlb
          service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: ip
          service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing
          service.beta.kubernetes.io/aws-load-balancer-security-groups: {SECURITY_GROUP_ID}
          service.beta.kubernetes.io/aws-load-balancer-attributes: load_balancing.cross_zone.enabled=true
```

### Configure DNS

Create a DNS record pointing to the load balancer's external IP:

```bash
# test DNS resolution (replace {DNS_URL} with your domain)
dig {DNS_URL}
```

### Configure ingress-values.yaml

Create a single `ingress-values.yaml` shared by all services:

#### HTTP Mode

```yaml
# ingress-values.yaml
httpProxy:
  enabled: true
  fqdn:
      domain: "{DNS_URL}" # e.g. my-company.storage-apis.example.com
```

#### HTTPS Mode

```yaml
# ingress-values.yaml
httpProxy:
  enabled: true
  fqdn:
      domain: "{DNS_URL}"
  tls:
      enabled: true
      secretName: storage-apis-cert
```

#### Auth Mode (with Envoy Auth Extension)

```yaml
# ingress-values.yaml
httpProxy:
  enabled: true
  fqdn:
      domain: "{DNS_URL}"
  tls:
      enabled: true
      secretName: storage-apis-cert
  authExtension:
      enabled: true
```

### TLS Certificate DNS Names

Get certificates for these DNS names:

```
"{DNS_URL}"
"storage.{DNS_URL}"
"event-aggregation.{DNS_URL}"
"event-consumer.{DNS_URL}"
"*.storage.{DNS_URL}"
"*.event-aggregation.{DNS_URL}"
"*.event-consumer.{DNS_URL}"
```

If deploying Storage Navigator, also add:

```
"navigator.{DNS_URL}"
"*.navigator.{DNS_URL}"
```

### Redeploy All Services with Ingress

```bash
# redeploy discovery service
helm upgrade --install discovery-service ./discovery-service -f ./discovery-service/discovery-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# test HTTP
curl http://{DNS_URL}/api/v1/services

# validate httpproxy resources
kubectl get httpproxy -n storage-apis

# redeploy storage service
helm upgrade --install storage-service ./storage-service -f ./storage-service/storage-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# if using notifications, redeploy those as well
helm upgrade --install event-aggregation-service ./event-aggregation-service -f ./event-aggregation-service/event-aggregation-values.yaml -f ./ingress-values.yaml --namespace storage-apis

helm upgrade --install event-consumer-service ./event-consumer-service -f ./event-consumer-service/event-consumer-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# validate httpproxy
kubectl get httpproxy -n storage-apis
```

After configuring HTTPS, redeploy all services again:

```bash
# test HTTPS
curl https://{DNS_URL}/api/v1/services
```

---

## Authentication (Optional)

Configure OpenID Connect (OIDC) authentication using the Envoy Auth Extension.

### Pull the Envoy Auth Extension Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/envoy-auth-extension-2.3.3.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf envoy-auth-extension-2.3.2.tgz
cd envoy-auth-extension
```

### Configure envoy-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
```

### Configure oidc-config.yaml

Replace `{tenant-id}` and `{client-id}` with values from your identity provider (e.g., Microsoft Entra ID):

```yaml
openId:
  enabled: true
  description: "My OIDC Configuration"
  openIdConfigurationUri: "https://login.microsoftonline.com/{tenant-id}/v2.0/.well-known/openid-configuration"
  clientRegistrations:
    - name: "default"
      clientId: "{client-id}"
      scope: "openid profile email offline_access {client-id}/.default"
```

### Install the Auth Extension

```bash
helm upgrade --install envoy-auth-extension . -f envoy-values.yaml -f oidc-config.yaml --namespace storage-apis

# validate
kubectl get pods -n storage-apis
```

### Redeploy Services with Auth

Update `ingress-values.yaml` to enable the auth extension (see Auth Mode in the Ingress section above), then redeploy all services:

```bash
# redeploy discovery service (includes oidc-config.yaml for auth-config endpoint)
helm upgrade --install discovery-service ./discovery-service -f ./discovery-service/discovery-values.yaml -f ./ingress-values.yaml -f ./oidc-config.yaml --namespace storage-apis

# redeploy storage service
helm upgrade --install storage-service ./storage-service -f ./storage-service/storage-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# if using notifications
helm upgrade --install event-aggregation-service ./event-aggregation-service -f ./event-aggregation-service/event-aggregation-values.yaml -f ./ingress-values.yaml --namespace storage-apis

helm upgrade --install event-consumer-service ./event-consumer-service -f ./event-consumer-service/event-consumer-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# redeploy storage navigator
helm upgrade --install storage-navigator ./storage-navigator -f ./storage-navigator/navigator-values.yaml -f ./ingress-values.yaml --namespace storage-apis

# validate
kubectl get pods -n storage-apis
```

### Validate Authentication

```bash
# check auth-config endpoint returns OIDC configuration
curl https://{DNS_URL}/api/v1/auth-config

# verify 401 on unauthenticated request
curl -vvv https://{DNS_URL}/api/v1/services
# expect HTTP/2 401 response with server: envoy
```

---

## Storage Navigator (Optional)

The Storage Navigator is a JavaScript web app for browsing and managing storage. Deploy it after your services and ingress are in place.

### CORS Configuration

Browser-based clients require CORS on the storage backend.

#### AWS S3 CORS

Create `cors.json`:

```json
[
  {
    "AllowedHeaders": ["*"],
    "AllowedMethods": ["GET", "PUT", "POST", "DELETE", "HEAD"],
    "AllowedOrigins": ["https://your-app-domain.com", "https://*.your-domain.com"],
    "ExposeHeaders": ["ETag", "Content-Length"],
    "MaxAgeSeconds": 3600
  }
]
```

Apply:

```bash
aws s3api put-bucket-cors --bucket BUCKET_NAME_HERE --cors-configuration file://cors.json
```

#### Azure Blob CORS

```bash
az storage cors add \
  --account-name <storage-account> \
  --services b \
  --methods GET PUT POST DELETE HEAD OPTIONS \
  --origins "https://your-app-domain.com" "https://*.your-domain.com" \
  --allowed-headers "*" \
  --exposed-headers "ETag" "Content-Length" \
  --max-age 3600
```

### Pull the Storage Navigator Chart

```bash
helm fetch https://helm.ngc.nvidia.com/nvidia/omniverse/charts/storage-navigator-1.0.1.tgz --username='$oauthtoken' --password=${NGC_API_KEY}

tar -xvf storage-navigator-0.0.46.tgz
cd storage-navigator
```

### Configure navigator-values.yaml

```yaml
image:
  pullSecrets:
    - name: ngcpull-secret
```

### Deploy

```bash
helm upgrade --install storage-navigator . -f navigator-values.yaml --namespace storage-apis

# validate
kubectl get pods -n storage-apis
```

### Navigator DNS Names

Ensure certificates cover these names:

```
"navigator.{DNS_URL}"
"*.navigator.{DNS_URL}"
```

### Deploy with Ingress

```bash
helm upgrade --install storage-navigator ./storage-navigator -f ./storage-navigator/navigator-values.yaml -f ./ingress-values.yaml --namespace storage-apis
```

Access the Navigator at `https://navigator.{DNS_URL}`.

---

## Layered Values Pattern

The deployment uses a layered values pattern where each Helm install command accepts multiple `-f` flags. Values files are applied in order, with later files overriding earlier ones:

1. **Base values** (`storage-values.yaml`, `discovery-values.yaml`, etc.) -- service-specific configuration
2. **ingress-values.yaml** -- shared ingress/DNS/TLS configuration
3. **oidc-config.yaml** -- shared OIDC authentication configuration (Discovery Service only)

### Full Redeployment Commands (All Layers)

```bash
# Discovery Service (base + ingress + OIDC)
helm upgrade --install discovery-service ./discovery-service \
  -f ./discovery-service/discovery-values.yaml \
  -f ./ingress-values.yaml \
  -f ./oidc-config.yaml \
  --namespace storage-apis

# Storage Service (base + ingress)
helm upgrade --install storage-service ./storage-service \
  -f ./storage-service/storage-values.yaml \
  -f ./ingress-values.yaml \
  --namespace storage-apis

# Event Aggregation Service (base + ingress)
helm upgrade --install event-aggregation-service ./event-aggregation-service \
  -f ./event-aggregation-service/event-aggregation-values.yaml \
  -f ./ingress-values.yaml \
  --namespace storage-apis

# Event Consumer Service (base + ingress)
helm upgrade --install event-consumer-service ./event-consumer-service \
  -f ./event-consumer-service/event-consumer-values.yaml \
  -f ./ingress-values.yaml \
  --namespace storage-apis

# Storage Navigator (base + ingress)
helm upgrade --install storage-navigator ./storage-navigator \
  -f ./storage-navigator/navigator-values.yaml \
  -f ./ingress-values.yaml \
  --namespace storage-apis

# Envoy Auth Extension (base + OIDC, no ingress-values needed)
helm upgrade --install envoy-auth-extension ./envoy-auth-extension \
  -f ./envoy-auth-extension/envoy-values.yaml \
  -f ./oidc-config.yaml \
  --namespace storage-apis
```

---

## Secrets Reference

| Secret Name | Namespace | Keys | Used By |
|------------|-----------|------|---------|
| `ngcpull-secret` | `storage-apis` | Docker registry credentials | All services (image pull) |
| `{mybucketname}-bucket-secret` | `storage-apis` | `BUCKET_ACCESS_KEY_ID`, `BUCKET_SECRET_ACCESS_KEY` | Storage Service (S3 credentials) |
| `{mystorageaccount}-container-secret` | `storage-apis` | `AZ_BLOB_STORAGE_KEY` | Storage Service (Azure credentials) |
| `rabbitmq-service-env` | `storage-apis` | `rabbitmq-password` | RabbitMQ (auth password) |
| `event-services-env` | `storage-apis` | `rabbitmq_uri` | Event Aggregation, Event Consumer (RabbitMQ connection) |
| `storage-notifications-secret` | `storage-apis` | `AZURE_SERVICE_BUS_POLICY_KEY`, `SQS_ACCESS_KEY_ID`, `SQS_SECRET_ACCESS_KEY`, `NOTIFICATION_SERVICE_CLIENT_SECRET` | Storage Service (notification credentials) |
| `storage-apis-cert` | `storage-apis` | TLS cert + key | Ingress (HTTPS termination) |

---

## Service Ports Reference

| Service | gRPC Port | REST Port | Other |
|---------|-----------|-----------|-------|
| Storage Service | 8011 | 8012 | -- |
| Discovery Service | -- | 8080 | -- |
| RabbitMQ | -- | -- | AMQP 5672 |
| Event Aggregation Service | 50051 | -- | -- |
| Event Consumer Service | -- | 8000 | -- |
| Storage Navigator | -- | 80 | Web UI |
| Envoy Auth Extension | -- | -- | Envoy sidecar |

---

## Validation

### Storage Service

```bash
# REST capabilities
curl http://storage-service.storage-apis.svc.cluster.local:8012/v1alpha/capabilities/services

# list a public S3 bucket
curl -v "http://storage-service.storage-apis.svc.cluster.local:8012/v1alpha/filefolder/list/https%3A%2F%2Fomniverse-content-production.s3.us-west-2.amazonaws.com%2F"

# port-forward alternative
kubectl port-forward -n storage-apis service/storage-service 8012:8012
curl http://localhost:8012/v1alpha/capabilities/services
```

### Discovery Service

```bash
curl http://discovery-service.storage-apis.svc.cluster.local:8080/api/v1/services

# port-forward alternative
kubectl port-forward -n storage-apis service/discovery-service 8080:8080
curl http://localhost:8080/api/v1/services
```

### Notifications Services

```bash
# port-forward the event consumer service
kubectl port-forward -n storage-apis deployment/event-consumer-service 8000:8000

# port-forward the storage service
kubectl port-forward -n storage-apis service/storage-service 8012:8012

# Terminal 1: subscribe to events
FILTERS='[
  {"event_type":"omni.storage.created","filters":[{"filter_type":"starts_with_greedy","resource_id":""}]},
  {"event_type":"omni.storage.deleted","filters":[{"filter_type":"starts_with_greedy","resource_id":""}]}
]'

curl -N -G "http://localhost:8000/api/v1beta/events/stream" \
  -H "Accept: text/event-stream" \
  --data-urlencode "filter_groups=$FILTERS"

# Terminal 2: trigger a storage event
export BUCKET_NAME=<YOUR_BUCKET_NAME>
export REGION=<YOUR_REGION>
curl -X PUT "http://localhost:8012/v1beta/fileobject/by-address/https%3A%2F%2F${BUCKET_NAME}.s3.${REGION}.amazonaws.com%2Fhello.txt?data_object_size=20" \
  -H "Content-Type: application/octet-stream" \
  --data "Hello from Storage API!"
```

### Ingress

```bash
# HTTP
curl http://{DNS_URL}/api/v1/services

# HTTPS
curl https://{DNS_URL}/api/v1/services

# verify httpproxy resources
kubectl get httpproxy -n storage-apis
```

### Authentication

```bash
# auth-config endpoint
curl https://{DNS_URL}/api/v1/auth-config

# verify 401 on unauthenticated request
curl -vvv https://{DNS_URL}/api/v1/services
```

### All Pods

```bash
kubectl get pods -n storage-apis
kubectl get services -n storage-apis
```

---

## Kit SDK Testing

Connect from the Omniverse Kit SDK to validate the full stack.

### Requirements

- Kit SDK 109.0.1 or later
- Download: [Linux](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/kit-sdk-linux) | [Windows](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/resources/kit-sdk-windows)

### Configuration

Set the `OMNI_STORAGE_DISCOVERY` environment variable before launching Kit. Add it to the Kit launch script (e.g., `omni.app.full.sh`) before the `${EXEC:-exec}` line:

```bash
# for HTTPS deployments
export OMNI_STORAGE_DISCOVERY=https://{discovery-url}

# for HTTP-only / local deployments
export OMNI_STORAGE_DISCOVERY=http://{discovery-url}
```

### Launch and Connect

1. Run the Kit launch script (e.g., `./omni.app.full.sh`).
2. Click **Add New Connection**.
3. Enter your storage URL in the Connection Path field.
4. Click **Add**.
5. Browse your bucket in the Content Browser. Try creating, opening, editing, and saving files to verify access.
