```mermaid
flowchart LR
  subgraph Cluster[Kubernetes Cluster]
    A[flask-demo (Helm release)] -->|metrics| P[Prometheus]
    A -->|logs| L[Loki]
    Argo[Argo CD] -->|sync| A
  end

  subgraph AIOps[AIOps Control Plane]
    Agent[AIOps Agent<br/>correlate/triage/llm/remediation] --> R[incident_report.json]
    Bot[Remediation Bot<br/>generate Helm patch + PR] --> GH[Git Repo PR]
  end

  P --> Agent
  L --> Agent
  R --> Bot
  GH --> Argo
```
