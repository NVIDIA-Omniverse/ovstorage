# Quick Start

## Accessing the NGC Catalog

To begin your journey, you will need to access the NGC org and team to gain access to the Omniverse Storage APIs specifications, pre-built containers, and helm charts. Follow the [instructions here](https://docs.nvidia.com/ngc/latest/ngc-catalog-user-guide.html) to set up your account.

Once you have access, work with your NVIDIA contact to make sure you are granted access to the **Omniverse Storage API enablement**. This will give you access to the [Omniverse Storage APIs Collection](https://catalog.ngc.nvidia.com/orgs/nvidia/teams/omniverse/collections/storage_apis) on NGC.

## Requirements

- Kubernetes **1.31+**
- kubectl
- Helm 3.0+

## Choose your Journey

### Example Adapter Stack

Python filesystem reference implementation + Discovery. For learning, development, and testing custom adapters. Deploy on any Kubernetes cluster (MicroK8s, EKS, AKS, GKE, bare metal).

See `references/deployment/example-adapter-stack.md`.

### Production Adapter Stack

NVIDIA pre-built S3/Azure adapter + Discovery as the minimum starting point. Expand with Notifications, Auth (Envoy Auth Extension), Navigator, and Contour as your needs require. Deploy on any Kubernetes cluster.

See `references/deployment/production-adapter-stack.md`.

### Custom Adapter Development

Build your own storage, notifications, or permissions adapter from the Omniverse Storage API specifications. Implement the gRPC/REST interfaces, integrate with your infrastructure, and validate against any deployment stack.

- Custom storage adapter: `references/development/custom-storage-adapter.md`
- Custom notifications adapter: `references/development/custom-notifications-adapter.md`
- Custom permissions adapter: `references/development/custom-permissions-adapter.md`
