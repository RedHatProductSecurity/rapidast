# RapiDAST

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/redhatproductsecurity/rapidast/run-tests.yml?branch=development&logo=github&label=CI) ![GitHub License](https://img.shields.io/github/license/redhatproductsecurity/rapidast)

RapiDAST (Rapid DAST) is an open-source security testing tool that automates DAST ([Dynamic Application Security Testing](https://owasp.org/www-project-devsecops-guideline/latest/02b-Dynamic-Application-Security-Testing)) and streamlines the integration of security testing into development workflows. It is designed to help Developers and/or QA engineers rapidly and effectively identify low-hanging security vulnerabilities in your applications, ideally in CI/CD pipelines. RapiDAST is for organizations implementing DevSecOps with a shift-left approach.

RapiDAST provides:

- Automated HTTP/API security scanning leveraging ZAP
- Automated LLM AI scanning leveraging Garak
- Kubernetes operator scanning leveraging OOBTKUBE
- Automated vulnerability scanning using Nessus (requires a Nessus instance)
- Command-line execution with yaml configuration, suitable for integration in CI/CD pipelines
- Ability to run automated DAST scanning with pre-built or custom container images
- HTML, JSON and XML report generation
- Integration with Google Cloud Storage and OWASP DefectDojo

RapiDAST is for testing purposes, and should not be used on production systems.

See [User Guide](./USER-GUIDE.md)<br />
See [Developer Guide](./DEVELOPER-GUIDE.md)

## Contributing

Contribution to the project is more than welcome.

See [CONTRIBUTING.md](./CONTRIBUTING.md)
