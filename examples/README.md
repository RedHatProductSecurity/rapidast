# Examples

The code examples in this directory show how RapiDAST can be run in various CI/CD pipelines. For RapiDAST configuration templates, see [here](../config).

## Recommendations

The recommended strategy for integrating RapiDAST in CI/CD pipelines is to build the target application as a container image, deploy it in the pipeline, then pull down the RapiDAST container image and launch a RapiDAST scan.

Running both the target application and RapiDAST in containers simplifies the work needed to bootstrap both (e.g. skipping dependency installation) and provides strong guarantees on stability and reproducibility.
