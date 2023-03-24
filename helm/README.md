RapiDAST scans can be performed by using the Helm chart included in the repository

Consult https://helm.sh/docs/intro/quickstart/ to install Helm.

`values.yaml` contains various configuration items including RapiDAST config and default scan policy. The config can be overridden by using `--set-file`, `--set` or `-f`.

For example, using `--set-file config`, it is possible to update configuration for RapiDAST scans.

```
$ helm install rapidast ./helm-chart/ --set-file config=<your-rapidast-config.yaml>
```

It is also possible to override the scan policy in the same way.

```
$ helm install rapidast ./helm-chart/ --set-file scanPolicyXML=<your-custom-scan-policy.xml>
```
