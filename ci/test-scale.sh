#!/usr/bin/env bash

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_DIR=$THIS_DIR/..
# Well known kubeconfig path.
BASE_KUBECONFIG="$HOME/.kube/config"
KUBECONFIG="/tmp/admin.conf"
ANTREA_YML="/tmp/antrea.yml"

# Generate antrea yaml for scale test, the yaml makes agent will not be scheduled to simulator nodes.
"$REPO_DIR"/hack/generate-manifest.sh --mode dev --simulator > $ANTREA_YML
kubectl apply -f $ANTREA_YML

kubectl create configmap node-configmap -n kube-system --from-literal=content.type="test-cluster"

# Try best to clean up.
kubectl delete -f "$REPO_DIR/build/yamls/antrea-agent-simulator.yaml" || true
kubectl delete secret kubeconfig || true

cp "$BASE_KUBECONFIG" $KUBECONFIG
# Create simulators.
kubectl create secret generic kubeconfig --type=Opaque --namespace=kube-system --from-file $KUBECONFIG
kubectl apply -f "$REPO_DIR/build/yamls/antrea-agent-simulator.yaml"

# Create scale test job.
kubectl apply -f "$REPO_DIR/build/yamls/antrea-scale.yaml"
