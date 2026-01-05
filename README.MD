# aiops-agent (Python)

Python AIOps agent for AKS-style environments using **Prometheus + Loki**.

It generates a small **incident context report** by querying:
- Prometheus: basic namespace health signals (pod restarts, running pods)
- Loki: recent error logs for a namespace/app label

Outputs:
- A JSON report for audit/replay
- A terminal summary rendered with `rich`

## Requirements

- Python >= 3.11
- [`uv`](https://github.com/astral-sh/uv) (recommended)
- Access to Prometheus and Loki HTTP APIs (commonly via `kubectl port-forward`)

## Install

```bash
uv sync --reinstall
```

## Configuration

The CLI reads settings from environment variables (with defaults):

```bash
export PROM_URL="http://localhost:9090"
export LOKI_URL="http://localhost:3100"
export NAMESPACE="default"
export APP_LABEL="flask-demo"
export LOOKBACK_MIN="15"

# optional auth (for future/secured endpoints)
export BEARER_TOKEN="..."      # optional
export BASIC_USER="..."        # optional
export BASIC_PASS="..."        # optional
```

## Usage

Generate an incident report:

```bash
uv run aiops incident --out incident_report.json
cat incident_report.json
```

## Kubernetes demo app

This repo includes a tiny Flask app that:
- exposes Prometheus metrics at `/metrics`
- emits an ERROR log at `/error` (useful for Loki ingestion)

Apply it:

```bash
kubectl apply -f test/flask_demo.yaml
```

## Observability stack (Prometheus + Loki)

The included `Manual.MD` shows one way to install these via Helm.

### Prometheus (kube-prometheus-stack)

```bash
kubectl create ns monitoring

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack -n monitoring

kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090:9090
```

Verify:

- http://localhost:9090

### Loki (loki-stack + promtail)

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm upgrade --install loki grafana/loki-stack \
  -n monitoring --create-namespace \
  --set loki.isDefault=true \
  --set promtail.enabled=true \
  --set grafana.enabled=false

kubectl -n monitoring get pods | egrep "loki|promtail"
kubectl -n monitoring get svc | egrep "loki"

kubectl -n monitoring port-forward svc/loki 3100:3100
curl -s http://localhost:3100/ready && echo
```

## What the agent queries

- Prometheus (instant queries):
  - container restarts (lookback window)
  - running pods in the namespace
- Loki (range query):
  - `{namespace="...", app="..."} |~ "(?i)error"` (samples up to 20 recent lines)

## Development notes

- CLI entrypoint: `aiops_agent/cli.py` (Typer)
- Settings: `aiops_agent/config.py`
- Collectors: `aiops_agent/collector/prometheus.py`, `aiops_agent/collector/loki.py`

