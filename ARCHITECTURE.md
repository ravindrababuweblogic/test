# Simple-Java-App Architecture

## System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        A[HTTP Clients]
    end

    subgraph "Load Balancing"
        B[Kubernetes Service<br/>ClusterIP]
    end

    subgraph "Application Layer"
        C1["simple-java-app Pod 1<br/>Spring Boot App"]
        C2["simple-java-app Pod 2<br/>Spring Boot App"]
        C3["simple-java-app Pod N<br/>Spring Boot App"]
    end

    subgraph "Scaling"
        D[HPA<br/>2-10 Replicas]
    end

    subgraph "Monitoring"
        E1[Prometheus]
        E2[Health Checks]
    end

    subgraph "Container Registry"
        F["GHCR Image<br/>ghcr.io/user/simple-java-app"]
    end

    A -->|HTTP/HTTPS| B
    B -->|Port 8080| C1
    B -->|Port 8080| C2
    B -->|Port 8080| C3
    D -.->|scales| C3
    C1 -->|metrics| E1
    C1 -->|liveness| E2
    F -.->|pulls| C1
