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
  volumes:
    - name: results-volume
      persistentVolumeClaim:
        claimName: $PVC
EOF

oc apply -f $TMP_DIR/$RANDOM_NAME
rm $TMP_DIR/$RANDOM_NAME
oc wait --for=condition=Ready pod/$RANDOM_NAME
oc rsync $RANDOM_NAME:/zap/results $RESULTS_DIR
oc delete pod $RANDOM_NAME

