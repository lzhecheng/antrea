#!/bin/bash
echo "=== delete antrea ==="
kubectl delete -f build/yamls/antrea.yml

echo "=== make ==="
make bin
make ubuntu

echo "=== docker save antrea ==="
docker save antrea/antrea-ubuntu:latest > antrea.tar

workers=(zhecheng-k8s0-1 zhecheng-k8s0-2)
for worker in "${workers[@]}"
do
        echo "=== deliver to ${worker} ==="
        cp antrea.tar /home/ubuntu
        su - ubuntu -c "scp /home/ubuntu/antrea.tar ${worker}:~"
        su - ubuntu -c "ssh ${worker} 'sudo docker load -i antrea.tar'"
done

echo "=== start antrea ==="
kubectl apply -f build/yamls/antrea.yml

kubectl get pods -A
