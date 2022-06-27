# rapidast-operator
The RapiDAST operator makes it possible to configure RapiDAST scans from your OpenShift or Kubernetes cluster. This allows you to scan your APIs from both inside and outside of your cluster.

## Custom Resource Definitions
The RapiDAST operator extends the RapiDAST custom resource definition (CRD) 

## Installing the Operator

There are multiple ways to install the operator onto your cluster. Read through, and select the method that best suits your situation.

### Install via Operator Lifecycle Manager (OLM)
If your cluster has OLM installed, you can use it to install and manage the RapiDAST operator. You can follow the installation instructions [here](https://github.com/operator-framework/operator-lifecycle-manager/blob/master/doc/install/install.md). If you're running on an OpenShift cluster, you likely have this installed by default.

For the example outlined here, a namespace `rapidast` has already been created on the cluster. Should you desire to install the operator to another namespace, update the YAML accordingly.

Install the operator by adding the following CatalogSource, Subscription, and OperatorGroup resources to your cluster.

As a convenience, you may use the file olm/rapidast.yaml to apply all three resources to the `rapidast` namespace at once with
`kubectl apply -f olm/rapidast.yaml`

If you prefer to add resources individually, follow instructions below.

#### Add CatalogSource
Create a catalog source in a file `catalogsource.yaml` with the following contents. Update the value for namespace as required.

```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: CatalogSource
metadata:
  name: rapidast-catalog
  namespace: rapidast
spec:
  sourceType: grpc
  image: quay.io/redhatproductsecurity/rapidast-operator-catalog:v0.0.1
```
Apply the resource to your cluster
```bash
kubectl apply -f catalogsource.yaml
```

#### Add Subscription
Create a subscription in a file `subscription.yaml` with the following contents, updating the namespace to match the configuration of your cluster.
```yaml
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  name: rapidast-operator
  namespace: rapidast
spec:
  channel: alpha
  installPlanApproval: Automatic
  name: rapidast-operator
  source: rapidast-catalog
  sourceNamespace: rapidast
```
Now apply the subscription to your cluster 
```bash
kubectl apply -f subscription.yaml
```

#### Add OperatorGroup
Create a file `operatorgroup.yaml` with the following contents, updating the namespace as necessary to match the configuration of your cluster.

```yaml
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: rapidast-operator
  namespace: rapidast
spec:
```

Apply the OperatorGroup to your cluster with
```bash
kubectl apply -f operatorgroup.yaml
```

### Helm
As an alternative to the operator, it is possible to set up a scan by installing the included helm chart
```bash
helm install -f overrides.yaml rapidast-operator ./helm-charts/rapidast-chart
```
Where `overrides.yaml` should hold the configuration for your scan based on the values as described in the following section.

## Setting Up for a Scan

Setting up for a scan involves creating a YAML file to define the RapiDAST custom resource. The example shown here is also available in `config/samples/research_v1alpha1_rapidast.yaml`

You should change the name of the resource (`metadata.name`) something that best reflects the application being scanned.

```yaml
apiVersion: research.psse/v1alpha1
kind: RapiDast
metadata:
  name: rapidast-sample
spec:
  # Default values copied from <project_dir>/helm-charts/rapidast-chart/values.yaml
  config: |-
    general:
      serviceName: 'demo1'
      resultDir: '/results/'
      appDir: '/zap'
      localProxy: {"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}
      sessionName: 'session1'
      shutdownOnceFinished: False
  
    openapi:
      importFromUrl: True
      url: "http://localhost:9001/openapi.yaml"
  
      # if import_from_url is False, set a directory to contain OAS definition files
      directory: "/zap/config/oas"
  
    scan:
      contextName: 'context1'
  
      target: 'http://localhost:9000/api/'
      contextIncludeURL: ['http://localhost:9000/api/.*']
  
      # applicationURL is used for a starting point when crawling is required
      applicationURL: ''
  
      # Define Context Exclude URL regular expressions.
      # The UI uses dynamic hashes in the filename to avoid being cached.
      # Exclude this to avoid the spider getting trap endessly in the UI site tree
      contextExcludeURL: ['']
  
  
      #### SCAN POLICIES ####
      policies:
        # active scan
        scanPoliciesDir: '/zap/policies'
        scanPolicyName: 'API-minimal-example'
  
        # passive scan
        disabledPassiveScan: "2,10015,10027,10096,10024"
        # https://www.zaproxy.org/docs/alerts/
        # 2: Private IP Disclosure
        # 10015: Incomplete or No Cache-control Header Set
        # 10027: Information Disclosure - Suspicious Comments
        # 10096: Timestamp Disclosure
        # 10024: sensitive info in URL
  
      #### AUTHENTICATION ####
      # Define authentication method for the context. Possible values are:
      # "null", "manualAuthentication"; "scriptBasedAuthentication"; "httpAuthentication";
      # "formBasedAuthentication"
      authMethod: null
  
      #### UPSTREAM PROXY ####
      proxy:
        useProxyChain: False
        proxyAddress: ''
        proxyPort: ''
        skipProxyAddresses: ('127.0.0.1;', 'localhost')
  image:
    pullPolicy: Always
    repository: quay.io/redhatproductsecurity/rapidast
    tag: latest
  job:
    cron: false
    schedule: '* * * * *'
  pvc: rapidast-pvc
```

### RapiDAST Config

Most of the application specific scan configuration exists under `spec.config`. This is itself YAML syntax included here as a multiline string. This is the same configuration used in the core RapiDAST project [here](https://github.com/RedHatProductSecurity/rapidast/blob/development/config/config-template-local.yaml)

#### Operator Config Options
There are additional config options specific to the operator.

##### image
Under image, you can change the pull policy, repository, and tag for the rapidast image. Unless testing changes, these are best left to their default values.

##### job
Under job, there are two options. 
- cron: This is a boolean value. If true, will run RapiDAST scans on the specified schedule
- schedule: Defines the schedule used if cron is set to true. This uses 

##### pvc
The `pvc` specifies the persistent volume claim to use. This is used by the operator to store results. If the specified PVC does not exist, it will be created. Note that this will not be uninstalled should you delete the RapiDAST resource, and will need to be explicitly deleted by itself when you are sure you don't need any of the data contained on the bound volume.

### Apply RapiDAST Resource

To apply the RapiDAST resource to the cluster you are already logged into, run

`kubectl apply -f rapidast.yaml`

where `rapidast.yaml` is modified to the filename used for your RapiDAST CR.

#### Demo application
An application for demonstration purposes is available [here](https://github.com/jpweiser/rapitester). You can use this application, and the provided configuration to see the RapiDAST operator at work.

## Getting Results

The easiest way to get results is to use a pod that mounts the same PVC used to store the results, and use `kubectl cp POD:/results_dir local_dir` to copy an entire directory, or `kubectl cp POD:/path/to/file /local/path` for a single file.

For convenience, a script `results.sh` is provided. It will create a pod mounting the specified PVC, then use `kubectl cp` to copy the entire results directory to your specified local directory before deleting the pod.

Run this script with
```bash
bash results.sh <PVC> <LOCAL_RESULTS_DIR>
```

## Development

### Building Bundle and Catalog
The following one-liner will both build and push the bundle and catalog images.
```bash
make bundle bundle-build bundle-push catalog-build catalog-push
```
