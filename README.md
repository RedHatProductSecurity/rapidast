# RapiDAST

RapiDAST(Rapid DAST) is an open-source security testing tool that automates the process of DAST(Dynamic application security testing) security testing and streamlines the integration of security into your development workflow. It is designed to help you quickly and effectively identify security vulnerabilities in your applications.

Taking advantage of [OWASP ZAP](https://www.zaproxy.org/) and additional scanners(TBD), RapiDAST provides additional value as follows:

- Ease of use and simple automation of HTTP/API scanning, fully working in CLI with a yaml configuration
- Ability to run automated DAST scanning to suit various users' needs
- HTML, JSON and XML report generation
- Integration with reporting solutions (TBD)

# Getting Started

## Prerequisites

- `python` >= 3.5
    + because of subprocess.run
- `podman`
    + Some scanners (such as the ZAP scanner) may spawn a container using podman
- See `requirements.txt` for a list of required python libraries

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

It is possible to choose the method to spawn a scanner using `scanners.<name>.container.type` configuration.
Currently accepted value to choose among :
+ `podman`:
    - Select the image to load from `scanner.<name>.container.image` (sensible default are provided for each scanner)
+ `none`:
    - The scanner is run locally, no container used
    - The scanner needs to be already installed on the host
    - __Warning__: without a container layer, RapiDAST may have to modify the host's file system, such as the tools configuration to fit its needs. For example: the ZAP plugin has to copy the policy file used in ZAP's user config directory (`~/.ZAP`)


The user can set `general.container.type` to set this type for each scanner at once.

### Scanners

#### ZAP

OWASP® ZAP (Zed Attack Proxy) is an open-source Web Scanner. It can be used for scanning web applications and API.

See https://www.zaproxy.org/ for more information.

This scanner will download a ZAP container image and execute it given the configuration provided.

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
