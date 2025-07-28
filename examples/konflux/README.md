# RapiDAST in Konflux

In Konflux, the recommended approach for running RapiDAST is to use it in an IntegrationTest, where the application components built
previously can be deployed and scanned.

See the example [Pipeline](./integration-test.yaml), for an approach that uses [eaas-provision-space](https://github.com/konflux-ci/build-definitions/tree/main/task/eaas-provision-space/0.1) to obtain an environment for deploying components. This pipeline references as
a separate, standalone [RapiDAST task](./rapidast-check.yaml), which may in the future be stored and published from a central location.

## Notes

- This example is suitable for lower privileged components, that do not require cluster-admin to install. Higher privileged components, like cluster Operators
can use the [create-ephemeral-cluster stepaction](https://github.com/konflux-ci/build-definitions/tree/main/stepactions/eaas-create-ephemeral-cluster-hypershift-aws/0.1).
- This example makes use of `oc port-forward` to make deployed components accessible to RapiDAST from an remote location. This means the RAPIDAST_CONFIG_VALUE
parameter passed to this task should only include localhost URLs, not remote URLs
- This example uses SCAN_OUTPUT to provide UI indicators of detected issues. This is typically only used elsewhere in the clair scan tasks (not sast tasks), and
may be removed in favour of only using TEST_OUTPUT
- This example currently does not include a step to push SARIF results to quay.io using oras, similar to SAST related tasks. This may be added in the future
