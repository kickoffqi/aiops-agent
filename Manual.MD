#System Variables to exported to your local environment
export PROM_URL="http://localhost:9090"
export LOKI_URL="http://localhost:3100"
export NAMESPACE="default"
export APP_LABEL="flask-demo"
export LOOKBACK_MIN="15"

#Demo application for K8s
aiops-agent-python/test/flask_demo.yaml


#Install Prometheus
    #Create monitorying namespace
    kubectl create ns monitoring

    #Add Helm lib
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo add grafana https://grafana.github.io/helm-charts
    helm repo update

    #Install kube-prometheus-stack
    helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
        -n monitoring

    #Check pods for Prometheus
    kubectl -n monitoring get pods
        •	prometheus
        •	alertmanager
        •	grafana
        •	node-exporter
        •	kube-state-metrics

    #Prometheus port-forward
    kubectl -n monitoring port-forward svc/kube-prometheus-stack-prometheus 9090:9090

    #Check Prometheus
    http://localhost:9090


#Install Loki && Using local filesyste for storage
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm upgrade --install loki grafana/loki-stack \
  -n monitoring --create-namespace \
  --set loki.isDefault=true \
  --set promtail.enabled=true \
  --set grafana.enabled=false

#Check Loki pods and svc
kubectl -n monitoring get pods | egrep "loki|promtail"
kubectl -n monitoring get svc | egrep "loki"

#Loki port-forward
kubectl -n monitoring port-forward svc/loki 3100:3100

#Check Loki url
curl -s http://localhost:3100/ready && echo

#How To Run(Using UV)

find . -name "__pycache__" -type d -exec rm -rf {} +
uv sync --reinstall
uv run aiops incident --out incident_report.json
uv run aiops --out incident_report.json
uv run aiops incident --out incident_report.json
cat incident_report.json


uv run aiops incident --out incident_report.json

#Azure K8s login clis
az account show
az aks list -o table
az aks get-credentials -g rg-aks-platform-dev -n aks-platform-dev --overwrite-existing
kubectl get ns