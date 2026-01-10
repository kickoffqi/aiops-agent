#Upgrade Helm values_config.yaml setting
helm upgrade --install flask-demo ../flask-demo -f values.yaml -f values_config.yaml
kubectl -n default get svc flask-demo -o yaml | sed -n '1,120p'

