#Confirm your Azure account and K8s details
az aks get-credentials -g rg-aks-platform-dev -n aks-platform-dev --overwrite-existing
kubectl config current-context
kubectl get nodes


#Create your docker and push
docker buildx build --platform linux/amd64 -t kickoffqi/flask-demo:aiops-lab-v2 --push .
kubectl -n default set image deploy/flask-demo flask-demo=kickoffqi/flask-demo:aiops-lab-v2
kubectl -n default rollout status deploy/flask-demo
