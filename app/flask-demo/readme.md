#Upgrade Helm values_config.yaml setting
helm upgrade --install flask-demo ../flask-demo -f values.yaml -f values_config.yaml
kubectl -n default get svc flask-demo -o yaml | sed -n '1,120p'

helm upgrade --install flask-demo ../flask-demo -n default
kubectl -n default port-forward svc/flask-demo 8080:8080
curl -i http://localhost:8080/
curl -i http://localhost:8080/config

helm upgrade --install flask-demo ../flask-demo -n default \
  --set app.requiredToken=""
curl -i http://localhost:8080/config
# 期待：log 中出现 error_type=config

helm upgrade --install flask-demo ../flask-demo -n default \
  --set app.mode=dependency_fail
# 期待：error_type=dependency


helm upgrade --install flask-demo ../flask-demo -n default \
  --set faults.portMismatch.enabled=true \
  --set faults.portMismatch.serviceTargetPort=80

# port-forward 仍然是 svc:8080（service.port），但 service 会打到 pod:80 => connection refused
kubectl -n default port-forward svc/flask-demo 8080:8080
curl -i http://localhost:8080/config
# 期待：连接失败/empty reply/connection refused => Loki/你的 AIOps 里归类到 config（port mismatch）


#Same tag
helm upgrade --install flask-demo ../flask-demo -n default \
  --set rollout.force="$(date +%s)"