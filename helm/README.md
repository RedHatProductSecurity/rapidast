RapiDAST scans can be performed by using the Helm chart included in the repository. Consult https://helm.sh/docs/intro/quickstart/ to install Helm.

The Helm chart uses the official RapiDAST image: `quay.io/redhatproductsecurity/rapidast:latest`.

`values.yaml` contains various configuration items including a RapiDAST config template and default scan policy. Either you modify it for your environment or override by using `--set-file`, `--set` or `-f`.

For example, using `--set-file rapidastConfig`, it is possible to update configuration for RapiDAST scans.

```
$ helm install rapidast ./helm/chart/ --set-file rapidastConfig=<your-rapidast-config-with-container-type-none.yaml>
```

**NOTE**: general.container.type or scanners.<name>.container.type in the config must be `none` as scanners are already built in the rapidast image.

It is also possible to override the scan policy in the same way.

```
$ helm install rapidast ./helm/chart/ --set-file scanPolicyXML=<your-custom-scan-policy.xml>
```

#### Getting Results

Once the scan has been finished, the result is stored in PersistentVolume (default: through PersistentVolumeClaim(PVC), which is rapidast-pvc. See the charts/values.yaml.)

The easiest way to get results is to use a pod that mounts the same PVC used to store the results, and use `kubectl cp POD:/results_dir local_dir` to copy an entire directory, or `kubectl cp POD:/path/to/file /local/path` for a single file.

For convenience, a script results.sh is provided. It will create a pod mounting the specified PVC, then use `kubectl cp` to copy the entire results directory to your specified local directory before deleting the pod.

Run this script with

```
$ bash results.sh <PVC> <LOCAL_RESULTS_DIR>
```

#### Running on OpenShift

When running on OpenShift, make sure that your namespace you are running on has proper privileges for running a pod/container

You'll need to set `secContext: '{"privileged": true}'` at [https://github.com/RedHatProductSecurity/rapidast/blob/development/helm/chart/values.yaml#L14](https://github.com/RedHatProductSecurity/rapidast/blob/development/helm/chart/values.yaml#L14)

