#!/bin/bash

# The script runs Network Policy Cyclonus tests on a existing cluster
# Parameters:
# CLUSTER_NAME: name of the cluster
# KUBECONFIG: Set the variable to the cluster kubeconfig file path
# REGION: defaults to us-west-2
# IP_FAMILY: defaults to IPv4
# ADDON_VERSION: Optional, defaults to the latest version
# ENDPOINT: Optional
# DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE: false
# NP_CONTROLLER_ENDPOINT_CHUNK_SIZE: Optional
# AWS_EKS_NODEAGENT: Optional
# AWS_CNI_IMAGE: Optional
# AWS_CNI_IMAGE_INIT: Optional

set -euoE pipefail
DIR=$(cd "$(dirname "$0")"; pwd)

source ${DIR}/lib/cleanup.sh
source ${DIR}/lib/network-policy.sh
source ${DIR}/lib/tests.sh

: "${ENDPOINT_FLAG:=""}"
: "${ENDPOINT:=""}"
: "${ADDON_VERSION:=""}"
: "${IP_FAMILY:="IPv4"}"
: "${REGION:="us-west-2"}"
: "${SKIP_ADDON_INSTALLATION:="false"}"
: "${ENABLE_STRICT_MODE:="false"}"
: "${K8S_VERSION:=""}"
: "${TEST_IMAGE_REGISTRY:="registry.k8s.io"}"
: "${PROD_IMAGE_REGISTRY:=""}"
: "${DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE:="false"}"
: "${NP_CONTROLLER_ENDPOINT_CHUNK_SIZE=""}}"
: "${AWS_EKS_NODEAGENT:=""}"
: "${AWS_CNI_IMAGE:=""}"
: "${AWS_CNI_INIT_IMAGE:=""}"

TEST_FAILED="false"

if [[ ! -z $ENDPOINT ]]; then
    ENDPOINT_FLAG="--endpoint-url $ENDPOINT"
fi

if [[ -z $K8S_VERSION ]]; then
    K8S_VERSION=$(aws eks describe-cluster $ENDPOINT_FLAG --name $CLUSTER_NAME --region $REGION | jq -r '.cluster.version')
fi

echo "Running Cyclonus e2e tests with the following variables
CLUSTER_NAME: $CLUSTER_NAME
REGION: $REGION
IP_FAMILY: $IP_FAMILY

Optional args
ENDPOINT: $ENDPOINT
ADDON_VERSION: $ADDON_VERSION
K8S_VERSION: $K8S_VERSION
"

echo "Nodes AMI version for cluster: $CLUSTER_NAME"
kubectl get nodes -owide

PROVIDER_ID=$(kubectl get nodes -ojson | jq -r '.items[0].spec.providerID')
AMI_ID=$(aws ec2 describe-instances --instance-ids ${PROVIDER_ID##*/} --region $REGION | jq -r '.Reservations[].Instances[].ImageId')
echo "Nodes AMI ID: $AMI_ID"

if [[ $SKIP_ADDON_INSTALLATION == "false" ]]; then
    load_addon_details

    if [[ ! -z $ADDON_VERSION ]]; then
        # Install the specified addon version
        install_network_policy_mao $ADDON_VERSION
    elif [[ ! -z $LATEST_ADDON_VERSION ]]; then
        # Install the latest addon version for the k8s version, if available
        install_network_policy_mao $LATEST_ADDON_VERSION
    else
        # Fall back to installing the latest version using helm
        install_network_policy_helm
    fi
else
    echo "Skipping addons installation. Make sure you have enabled network policy support in your cluster before executing the test"
fi

if [[ $DEPLOY_NETWORK_POLICY_CONTROLLER_ON_DATAPLANE == "true" ]]; then
    make deploy-network-policy-controller-on-dataplane NP_CONTROLLER_IMAGE=$PROD_IMAGE_REGISTRY NP_CONTROLLER_ENDPOINT_CHUNK_SIZE=$NP_CONTROLLER_ENDPOINT_CHUNK_SIZE
fi

run_cyclonus_tests

check_path_cleanup

if [[ $ENABLE_STRICT_MODE == "true" ]]; then

    echo "Running strict mode tests"
    if [[ ! -z $AWS_EKS_NODEAGENT ]]; then
        echo "Replacing Node Agent Image in aws-vpc-cni helm chart with $AWS_EKS_NODEAGENT"
        HELM_EXTRA_ARGS+=" --set nodeAgent.image.override=$AWS_EKS_NODEAGENT"  
    fi

    if [[ ! -z $AWS_CNI_IMAGE ]]; then
        echo "Replacing CNI Image in aws-vpc-cni helm chart with $AWS_CNI_IMAGE"
        HELM_EXTRA_ARGS+=" --set image.override=$AWS_CNI_IMAGE"  
    fi

    if [[ ! -z $AWS_CNI_INIT_IMAGE ]]; then
        echo "Replacing CNI Init Image in aws-vpc-cni helm chart with $AWS_CNI_INIT_IMAGE"
        HELM_EXTRA_ARGS+=" --set init.image.override=$AWS_CNI_INIT_IMAGE"
    fi

    install_network_policy_helm

    kubectl -n kube-system patch daemonset aws-node \
        --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/1/args/-", "value": "--enable-mode=\"strict\""}]'

    echo "Check aws-node daemonset status"
    kubectl rollout status ds/aws-node -n kube-system --timeout=300s

    pushd ${DIR}/../test/integration/strict
        CGO_ENABLED=0 ginkgo -v -timeout 15m --no-color --fail-on-pending -- --cluster-kubeconfig="$KUBECONFIG" --cluster-name="$CLUSTER_NAME" --test-image-registry=$TEST_IMAGE_REGISTRY || TEST_FAILED="true"
    popd

fi

if [[ $TEST_FAILED == "true" ]]; then
    echo "Test run failed"
    exit 1
fi
