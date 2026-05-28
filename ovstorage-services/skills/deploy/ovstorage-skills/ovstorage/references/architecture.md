# Architecture

The diagram below is the full suite of Omniverse Storage services that represent the feature set of Omniverse Enterprise Nucleus Server.

- **(Left) Client Applications:** On the left side of the diagram are client-side applications. These clients interact with the system through a consistent interface, connecting to service adapters via gRPC or REST APIs. This abstraction allows you to swap or update service adapter implementations without requiring changes to the client applications.

- **(Center) Service Adapters and Core Services:** The center of the diagram highlights the core services and service adapters. Green icons indicate services and adapters developed by NVIDIA, available through NGC. Red icons represent third-party services that can be integrated as needed. Each service adapter is modular, enabling you to tailor the architecture to your specific infrastructure requirements.

- **(Right) Infrastructure Services:** On the right, the diagram shows infrastructure services typically managed by your Cloud Service Provider (CSP) or internal infrastructure team. These components can be replaced or extended based on your deployment environment.

For more detailed documentation on each API and service adapter, refer to the [overview](overview.md#api-and-service-adapter-breakdown) section of this guide.

This architecture is designed for flexibility: you can replace or extend any of the generalized services shown in the diagram with your own custom service adapters or infrastructure components to best fit your deployment needs.

> **Cluster-agnostic:** This architecture can be deployed on any Kubernetes distribution including MicroK8s, EKS, AKS, GKE, or bare metal clusters. The choice of cluster target is independent of which services you deploy.

For deployment walkthroughs, see `references/deployment/`.
