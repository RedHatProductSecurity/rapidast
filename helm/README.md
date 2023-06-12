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


**NOTE**: When running on OpenShift make sure that your namespace you are running on has proper privileges for running a pod/container

As well as set secContext: '{ "privileged": true}' at top of ./chart/values.yaml
