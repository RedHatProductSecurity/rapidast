# RapiDAST

RapiDAST(Rapid DAST) is an open-source security testing tool that automates the process of DAST(Dynamic application security testing) security testing and streamlines the integration of security into your development workflow. It is designed to help you quickly and effectively identify security vulnerabilities in your applications.

Taking advantage of [OWASP ZAP](https://www.zaproxy.org/) and additional scanners(TBD), RapiDAST provides additional value as follows:

- Ease of use and simple automation of HTTP/API scanning, fully working in CLI with a yaml configuration
- Ability to run automated DAST scanning to suit various users' needs
- HTML, JSON and XML report generation
- Integration with reporting solutions (TBD)

# Getting Started

## Prerequisites

- `python` >= 3.6.8 (3.7 for MacOS/Darwin)
- `podman` >= 3.0.1
    + required when you want to run scanners from their container images, rather than installing them to your host.
- See `requirements.txt` for a list of required python libraries

### OS Support

Linux and MacOS are supported.

## Installation

It is recommended to create a virtual environment.
```
$ python3 -m venv venv
$ source venv/bin/activate
```

Install the project requirements.
```
(venv) $ pip install -U pip
(venv) $ pip install -r requirements.txt
```

# Usage

## Workflow

This section summarize the basic workflow as follows:
1. Create a configuration file for testing the application. See the 'configuration' section below for more information.
2. Optionally, an environment file may be added, e.g., to separate the secrets from the configuration file.
3. Run RapiDAST and get the results.

## Configuration

The configuration file is presented as YAML, and contains several main entries:
- `config` : contains `configVersion` which tells RapiDAST how to consume the config file
- `application` : contains data relative to the application being scanned : name, etc.
- `general` : contains data that will be used by all the scanners, such as proxy configuration, etc.
    + Each scanner can override an entry from `general` by creating an entry with the same name
- `scanners` : list of scanners, and their configuration

See `config/config-template.yaml`(a simple version) and `config/config-template-long.yaml`(an exhaustive version) for examples. Each can be used.

### Advanced configuration

You may not want to directly have configuration values inside the configuration. Typically: either the entry is a secret (such as a password), but the configuration needs to be public, or the entry needs to be dynamically generated (e.g.: a cookie, a uniquely generated URL, etc.) at the time of running RapiDAST, and it's an inconvenient to always having to modify the configuration file for each run.

To avoid this, RapiDAST proposes 2 ways to provide a value for a given configuration entry. For example, to provide a value for the entry `general.authentication.parameters.rtoken`, you can either (in order of priority):

- Create an entry in the configuration file (this is the usual method)
- Create an entry in the configuration file pointing to the environment variable that actually contains the data, by appending `_from_var` to the entry name: `general.authentication.parameters.rtoken_from_var=RTOKEN` (in this example, the token value is provided by the `$RTOKEN` environment variable)

### Defect Dojo integration

#### Preamble: creating Defect Dojo user

RapiDAST needs to be able to authenticate to Defect Dojo. However, ideally, it should have the minimum set of permissions, such that it will not be allow to modify products other than the one(s) it is supposed to.
In order to do that:
* create a user without any global role
* add that user as a "writer" for the product(s) it is supposed to scan

Then the product, as well as an engagement for that product, must be created in Defect Dojo. It would not be advised to give the RapiDAST user an "admin" role and simply set `auto_create_context` to True, as it would be both insecure and accident prone (a typo in the product name would let RapiDAST create a new product)

#### Defect Dojo configuration in RapiDAST

First, RapiDAST needs to be able to authenticate itself to a Defect Dojo service. This is a typical configuration:

```yaml
config:
  # Defect dojo configuration
  defectDojo:
    url: "https://mydefectdojo.example.com/"
    authorization:
      username: "rapidast_productname"
      password: "password"
      # alternatively, a `token` entry can be set in place of username/password
```

You can either authenticate using a username/password combination, or a token (make sure it is not expired). In either case, you can use the `_from_var` method described in previous chapter to avoid hardcoding the value in the configuration.

Then, RapiDAST needs to know, for each scanner, sufficient information such that it can identify which product/engagement/test to match.
This is configured in the `zap.scanner.defectDojoExport.parameters` entry. See the `import-scan` or  `reimport-scan` parameters at https://demo.defectdojo.org/api/v2/doc/ for a list of accepted entries.
Notes:
    * `engagement` and `test` refer to identifiers, and should be integers (as opposed to `engagement_name` and `test_title`
    * If a `test` identifier is provided, RapiDAST will reimport the result to that test. The existing test must be compatible (same file schema, such as ZAP Scan, for example)
    * If the `product_name` does not exist, the scanner should default to `application.productName`, or `application.shortName`
    * Tip: the entries common to all scanners can be added to `general.defectDojoExport.parameters`, while the scanner-dependant entries (e.g.: test identifier) can be set in the scanner's configuration (e.g.: `scanners.zap.defectDojoExport.parameters`)

```yaml
general:
  defectDojoExport:
    parameters:
      productName: "My product"
      tags: ["RapiDAST"]

scanners:
  zap:
    defectDojoExport:
      parameters:
        test: 34
        endpoint_to_add: "https://qa.myapp.local/"
```


## Execution

Once you have created a configuration file, you can run a scan with it.
```
$ rapidast.py --config <your-config.yaml>
```

There are more options.
```sh
usage: rapidast.py [-h] [--log-level {debug,info,warning,error,critical}]
                   [--config CONFIG_FILE] [--no-cleanup]

Runs various DAST scanners against a defined target, as configured by a
configuration file.

options:
  -h, --help            show this help message and exit
  --log-level {debug,info,warning,error,critical}
                        Level of verbosity
  --config CONFIG_FILE  Path to YAML config file
  --no-cleanup          Scanners to not cleanup their environment. (might be
                        useful for debugging purpose).
```

### Choosing the execution environment

Set `general.container.type` to select a runtime (default: podman)

Accepted values are as follows:
+ `podman`:
    - Set when you want to run scanners with their container images and use `podman` to run them.
    - RapiDAST must not run inside a container.
    - Select the image to load from `scanner.<name>.container.image` (sensible default are provided for each scanner)

+ `none`:
    - Set when you want to run scanners that are installed on the host or you want to build or run the RapiDAST image(scanners are to be built in the same image).
    - __Warning__: without a container layer, RapiDAST may have to modify the host's file system, such as the tools configuration to fit its needs. For example: the ZAP plugin has to copy the policy file used in ZAP's user config directory (`~/.ZAP`)

+ `flatpak`:
    - Runs the Flatpak version of ZAP (`org.zaproxy.ZAP` on `flathub`)
    - Flatpak must be installed, as well as `org.zaproxy.ZAP`
    - __Warning__: Flatpak's ZAP shares the user's home file system with the host, so RapiDAST may have to modify the host's file system, such as the tools configuration to fit its needs. For example: the ZAP plugin has to copy the policy file used in ZAP's user config directory (`~/.ZAP`)

It is also possible to set the container type for each scanner differently by setting `scanners.<name>.container.type` under a certain scanner configuration. Then the scanner will run from its image, regardless of the `general.container.type` value.

### Additional options

In `scanners.zap.miscOptions`, additional options can be provided :

+ enableUI (default: False): Runs ZAP with the UI (useful for debugging). The runtime type must support it (only `none` and `flatpak`)
+ updateAddons (default: True): Prior to running, ZAP will update its addons

Example:

```
scanners:
    zap:
        miscOptions:
            enableUI: True
            updateAddons: False
```

### Build a RapiDAST image

If you want to build your own RapiDAST image, run the following command.

```
$ podman build . -f containerize/Containerfile -t <image-tag>
```

Disclaimer: This tool is not intended to be run as a long-running service. Instead, it is designed to be run for a short period of time while a scan is being invoked and executed in a separate test environment. If this tool is used solely for the scanning purposes, vulnerabilities that are indicated to exist in the image will not have a chance to be exploited. This tool is provided "as is" and without any kind of warranty, either express or implied. The user assumes all risks and liability associated with its use.

### Running on Kubernetes or OpenShift

Helm chart is provided to help with running RapiDAST on Kubernetes or OpenShift.

See [helm/README.md](./helm/README.md)

### Scanners

#### ZAP

OWASP® ZAP (Zed Attack Proxy) is an open-source DAST tool. It can be used for scanning web applications and API.

See https://www.zaproxy.org/ for more information.

#### More scanners

TBD

### Authentication

Authentication is common to all scanners. Authentication is configured in the `general` entry. Not all scanners may support all authentication types.

Currently supported :

- No authentication: the scanners will communicate anonymously with the application

- OAuth2 using a Refresh Token:
This method describes required parameters needed to retrieve an access token, using a refresh token as a secret.
    + authentication type : `oauth2_rtoken`
    + parameters :
        * `token_endpoint` : the URL to which send the refresh token
        * `client_id` : the client ID
        * `rtoken_var_name`: for practical reasons, the refresh token is provided using environment variables. This entry describes the name of the variable containing the secret refresh token

- HTTP Basic:
This method describes the HTTP Basic Authorization Header. The username and password must be provided in plaintext and will be encoded by the scanners
    + authentication type: `http_basic`
    + parameters:
        * `username`
        * `password`

- Cookie Authentication:
This method describes authentication via Cookie header. The cookie name and value must be provided in plaintext.
    + authentication type: `cookie`
    + parameters:
        * `name`
        * `value`


# Troubleshooting

## Hitting docker.io rate limits

If you are unable to pull/update an image from docker.io due to rate-limit errors, authenticate to your Docker Hub account.

## "Error getting access token" using OAuth2

Possible pitfalls :

* Make sure that the parameters are correct (`client_id`, `token_endpoint`, `rtoken_var_name`) and that the refresh token is provided (via environment variable), and is valid
* Make sure you do not have an environment variable in your current environment that overrides what is set in the `envFile`

## Issues with the ZAP scanner

The best way to start is to look at the ZAP logs, which are stored in `~/.ZAP/zap.log` (within the container where ZAP was running)

Example with podman, considering that the container was not wiped (either `--no-cleanup`, or the container failed):

```sh
[rapidast-ng]$ podman container list --all
969d721cc5a8  docker.io/owasp/zap2docker-stable:latest  /zap/zap.sh -conf...  2 days ago   Exited (1) 2 days ago (unhealthy)              rapidast_zap_vapi_JxgLjx
[rapidast-ng]$ podman unshare
bash-5.2# podman mount rapidast_zap_vapi_JxgLjx
/home/cedric/.local/share/containers/storage/overlay/a5450de782fb7264ff4446d96632e6512e3ff2275fd05329af7ea04106394b42/merged
bash-5.2# cd /home/cedric/.local/share/containers/storage/overlay/a5450de782fb7264ff4446d96632e6512e3ff2275fd05329af7ea04106394b42/merged
bash-5.2# tail home/zap/.ZAP/zap.log

org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException: Failed to parse swagger defn null
2023-02-17 22:42:55,922 [main ] INFO  CommandLine - Job openapi added 1 URLs
2023-02-17 22:42:55,922 [main ] INFO  CommandLine - Job openapi finished
2023-02-17 22:42:55,923 [main ] INFO  CommandLine - Automation plan failures:
2023-02-17 22:42:55,923 [main ] INFO  CommandLine -     Job openapi target: https://vapi.example.com/api/vapi/v1 error: Failed to parse OpenAPI definition.

org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerException: Failed to parse swagger defn null
2023-02-17 22:42:55,924 [main ] INFO  Control - Automation Framework setting exit status to due to plan errors
2023-02-17 22:43:01,073 [main ] INFO  CommandLineBootstrap - OWASP ZAP 2.12.0 terminated.
```

## Caveats

* Currently, RapiDAST does not clean up the temporary data when there is an error. The data may include:
    + a `/tmp/rapidast_*/` directory
    + a podman container which name starts with `rapidast_`

This is to help with debugging the error. Once confirmed, it is necessary to manually remove them.

# Support

If you encounter any issues or have questions, please [open an issue](https://github.com/RedHatProductSecurity/rapidast/issues) on GitHub.

# Contributing

Contribution to the project is more than welcome.

See [CONTRIBUTING.md](./CONTRIBUTING.md)
