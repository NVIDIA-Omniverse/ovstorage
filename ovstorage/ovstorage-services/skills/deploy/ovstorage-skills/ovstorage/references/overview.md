# Omniverse Storage APIs and Service Adapter Developer Guide

## Overview

The Omniverse Storage APIs are a collection of gRPC and REST API specifications, along with microservice adapters. They are designed to work on top of your existing storage and infrastructure services, making it easy to use them directly within the Omniverse platform in a consistent way. These APIs offer features that were previously only available in the Nucleus Enterprise Server, but can now be used on your own custom infrastructure.

This guide is intended for developers and system administrators that are working to integrate the Omniverse platform directly into their infrastructure and workflows. You will learn how to use the APIs, create custom adapters, and create a deployment that you can use with Omniverse-based workflows.

## Guide Terminology

| Term | Description |
| --- | --- |
| Omniverse Storage APIs/API specifications | Generically refers to all of the gRPC or REST API specifications created by NVIDIA for storage and infrastructure services. |
| Service Adapter | A microservice that implements any of the Omniverse Storage API specifications. (e.g. AWS S3 **storage service**, connects to the S3 **storage service adapter**). |
| Service | A long running service that provides a specific functionality. (e.g. AWS S3 storage service, Derived Data Cache Service) |
| Client Application | An application or library that uses the API. (e.g. Storage Navigator, Kit Framework) |
| Deployment | Specific configurations of services, service adapters and their explicit versions to provide a specific access and functionality for end-users. |

## API and Service Adapter Breakdown

The Storage APIs are organized into multiple distinct service components, each focused on a specific area of storage functionality. The following services have released adapters available through NGC:

### Discovery

Enables the ability to have a single entry point for clients to discover and return a list of all the services used within a given Omniverse Storage deployment. Discovery is required in every deployment — it is how clients find and connect to all other services.

### Storage

Enables core storage operations for file, folder, and version capabilities. NVIDIA provides both a Python filesystem reference adapter (for learning and development) and a production S3/Azure adapter.

### Notifications

Enables real-time event streaming and notifications for storage operations, allowing clients to subscribe to and receive updates about file system changes.

Each API is designed to be used independently or together, allowing you to build a storage solution tailored to your infrastructure and workflow needs. However, our NVIDIA service adapter implementations leverage multiple APIs together to provide a full infrastructure solution.

> **Note:** The Permissions API has a published specification but no released service adapter. You can build a custom permissions adapter from the API spec — see `references/development/custom-permissions-adapter.md`.

## Deployment Paths

The deployment model has two independent axes: **service stack** (which adapters and services you deploy) and **cluster target** (which Kubernetes distribution you run on). These are orthogonal — any service stack can run on any cluster target.

### Example Adapter Stack

Python filesystem reference implementation + Discovery. This stack is designed for learning the Storage APIs, understanding the deployment process, and developing/testing custom adapters. See `references/deployment/example-adapter-stack.md`.

### Production Adapter Stack

NVIDIA pre-built S3/Azure adapter + Discovery as the minimum starting point. Add Notifications, Auth (Envoy Auth Extension), Navigator, and Contour incrementally as your needs grow. See `references/deployment/production-adapter-stack.md`.

> **Cluster target is orthogonal to stack choice.** Both stacks can be deployed on any Kubernetes distribution — MicroK8s, EKS, AKS, GKE, bare metal, or any other conformant cluster. Choose your cluster based on your infrastructure requirements, not your service stack.

## Sample Client Applications

### Storage Navigator

Provides a web-based file browser and management interface for interacting with Omniverse Storage, enabling users to browse, upload, download, and manage files and folders.
