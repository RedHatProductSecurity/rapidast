# RapiDAST

RapiDAST(Rapid DAST) provides a framework for automated DAST(Dynamic application security testing). It can be used by anyone who aims to improve the security of their products and services.

Its structure is as follow:

* `rapidast.py` does:
    + Loading the main configuration file
    + For each scanner activated by the config, runs it

* Currently, OWASP ZAP is supported, which will:
    + Translate the RapiDAST configuration to a ZAP Automation Framework configuration
    + Spawn a ZAP container image and run ZAP with the configuration
    + Save the result


# Requirements

- `python` >= 3.5
    + because of subprocess.run
- `podman`
    + Some scanners (such as the ZAP scanner) may spawn a container using podman
- See `requirements.txt` for a list of required python libraries

## Caveats

* Currently, RapiDAST can run only on a full fledged OS (bare metal or VM, but not as a container)
* Currently, RapiDAST does not cleanup the temporary data when there is an error. Data may include:
    + a `/tmp/rapidast_zap_*/` directory
    + a podman container which name starts with `rapidast_zap_`

To manually remove the podman containers :

```sh
 # 1. identify the container
$ podman container list --all
CONTAINER ID  IMAGE                                     COMMAND               CREATED         STATUS                               PORTS       NAMES
a8e1cc0f4bcc  docker.io/owasp/zap2docker-stable:latest  /zap/zap.sh -conf...  47 minutes ago  Exited (0) 39 minutes ago (healthy)              rapidast_zap_Vapi_OatVmy

 # 2. delete it
$ podman container rm rapidast_zap_Vapi_OatVmy
rapidast_zap_Vapi_OatVmy
```


# Usage

## Workflow

1. Write a configuration file for testing the application, which will include data such as:
    a. Application URL
    b. Authentication
    c. A config entry for each scanner to run. For example: a path to an OpenAPI or enabling spider(crawler) for ZAP
2. Optionally, an environment file may be added (to separate the secrets from the configuration file)
3. Run RapiDAST and wait for the results

## Configuration

The configuration is presented as YAML, and contains several main entries:
- `config` : contains `configVersion` which tells RapiDAST how to consume the config file
- `application` : contains data relative to the application being scanned : name, etc.
- `general` : contains data that will be used by all the scanners, such as proxy configuration, etc.
    + Each scanner can override an entry from `general` by creating an entry with the same name
- `scanners` : list of scanners, and their configuration

See `config/config-template.yaml` and `config/config-template-long.yaml` for examples.

## Execution

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

### Scanners

#### ZAP

OWASP® ZAP (Zed Attack Proxy) is an opensource Web Scanner. It can be used for scanning web applications and API.

See https://www.zaproxy.org/ for more information.

This scanner will download a ZAP container image and execute it given the configuration provided.

#### More scanners

TBD

### Authentication

Currently, Authentication is common to all scanner, and is configured in the `general` entry. Not all scanners may support all authentication types.

Currently supported :

- No authentication: the scanners will communicate anonymously with the application

- OAuth2 using a Refresh Token:
This method describes requires parameters needed to retrieve an access token, using a refresh token as a secret.
    + authentication type : `oauth2_rtoken`
    + parameters :
        * `token_endpoint` : the URL to which send the refresh token
        * `client_id` : the client ID
        * `rtoken_var_name`: for practical reasons, the refresh token is provided using environment variables. This entry describes the name of the variable containing the secret refresh token

- HTTP Basic
This method describes the HTTP Basic Authorization Header. The username/password must be provided in plaintext and will be encoded by the scanners
    + authentication type: `http_basic`
    + parameters:
        * `username`
        * `password`

- Cookie Authentication
This method describes authentication via Cookie header. The cookie name and value must be provded in plaintest.
    + authentication type: `cookie`
    + parameters:
        * `name`
        * `value`

```yaml
general:
  authentication:
    type: "oauth2_rtoken"
    parameters:
      client_id: "cloud-services"
      token_endpoint: "<token retrival URL>"
      rtoken_var_name: "RTOKEN"
```
# Troubleshooting

## Hitting docker.io rate limits

If you are often unable to pull/update an image from docker.io, you may try this method:
[Workaround docker rate limits](https://developers.redhat.com/blog/2021/02/18/how-to-work-around-dockers-new-download-rate-limit-on-red-hat-openshift#docker_s_new_rate_limit)

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
