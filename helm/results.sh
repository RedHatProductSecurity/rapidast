#!/bin/bash

# Temp directory to store generated pod yaml
TMP_DIR=/tmp

# Where to store sync'd results -- defaults to current dir
RESULTS_DIR=${2:-.}

# Name for rapiterm pod
RANDOM_NAME=rapiterm-$RANDOM

# Name of PVC in RapiDAST Resource, i.e. which PVC to mount to grab results
PVC=${1:-rapidast-pvc}

IMAGE_REPOSITORY=quay.io/redhatproductsecurity/rapidast-term

IMAGE_TAG=latest

cat <<EOF > $TMP_DIR/$RANDOM_NAME
apiVersion: v1
kind: Pod
metadata:
  name: $RANDOM_NAME
spec:
  containers:
    - name: terminal
      image: '$IMAGE_REPOSITORY:$IMAGE_TAG'
      command: ['sleep', '300']
      imagePullPolicy: Always
      volumeMounts:
        - name: results-volume
          mountPath: /zap/results/
      resources:
        limits:
          cpu: 100m
          memory: 500Mi
        requests:
          cpu: 50m
          memory: 100Mi
  volumes:
    - name: results-volume
      persistentVolumeClaim:
        claimName: $PVC
EOF

kubectl --kubeconfig=./kubeconfig apply -f $TMP_DIR/$RANDOM_NAME
rm $TMP_DIR/$RANDOM_NAME
kubectl --kubeconfig=./kubeconfig wait --for=condition=Ready pod/$RANDOM_NAME
kubectl --kubeconfig=./kubeconfig cp $RANDOM_NAME:/zap/results $RESULTS_DIR
kubectl --kubeconfig=./kubeconfig delete pod $RANDOM_NAME
