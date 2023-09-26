# RapiDAST

RapiDAST(Rapid DAST) is an open-source security testing tool that automates the process of DAST(Dynamic application security testing) security testing and streamlines the integration of security into your development workflow. It is designed to help you quickly and effectively identify security vulnerabilities in your applications.

Taking advantage of [ZAP](https://www.zaproxy.org/) and additional scanners(TBD), RapiDAST provides additional value as follows:

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

#### Note regarding MacOS and ZAP

RapiDAST supports executing ZAP on the host directly, or, experimentally, in podman. See [Choosing the execution environment](#choosing-the-execution-environment) for further information on configuring execution environments.

* When using ZAP directly on the host (`general.container.type: "none"` or `scanners.zap.container.type: "none"` in the configuration): you will need to configure `scanners.zap.container.parameters.executable` to the installation path of the `zap.sh` command, because it is not available in the PATH. Usually, its path is `/Applications/OWASP ZAP.app/Contents/Java/zap.sh`

Example:

```yaml
scanners:
  zap:
    container:
      type: none
      parameters:
        executable: "/Applications/OWASP ZAP.app/Contents/Java/zap.sh"
```

* When using "podman" as execution environemtn (`general.container.type: "podman"` or `scanners.zap.container.type: "podman"` in the configuration): This mode is currently experimental. You will need to start the podman virtual machine sharing both the `rapidast` directory as well as the current temporary directory.

Example:

```sh
podman machine init -v "$PWD:$PWD" -v "$TMPDIR:$TMPDIR" rapidast
podman machine start rapidast
./rapidast --config ./config/<config-file>

 # after successful run, when the VM is no longer needed:
podman machine stop rapidast
podman machine rm rapidast
```



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
    - First run with passive scanning only which can save your time at the initial scanning  phase. There are various situations that can cause an issue, not only from scanning set up but also from your application or test environment. Active scanning takes a long time in general.
    - Once passive Scanning has run successfully, run another scan with active scanning enabled in the configuration file.

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

#### Running several instance of a scanner

It is possible to run a scanner several times with different configurations. This is done by giving adding a different identifier to each scan, by appending `_<id>` to the scanner name.

For example :

```yaml
scanners:
  zap_unauthenticated:
    apiScan:
      apis:
        apiUrl: "https://example.com/api/openapi.json"

  zap_authenticated:
    authentication:
      type: "http_basic"
      parameters:
        username: "user"
        password: "mypassw0rd"
    apiScan:
      apis:
        apiUrl: "https://example.com/api/openapi.json"
```

In the example above, the ZAP scanner will first run without authentication, and then rerun again with a basic HTTP authentication.
The results will be stored in their respective names (i.e.: `zap_unauthenticated` and `zap_authenticated` in the example above).

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

It is also possible to set the container type for each scanner differently by setting `scanners.<name>.container.type` under a certain scanner configuration. Then the scanner will run from its image, regardless of the `general.container.type` value.

### Additional options


### Build a RapiDAST image

If you want to build your own RapiDAST image, run the following command.

```
$ podman build . -f containerize/Containerfile -t <image-tag>
```

Disclaimer: This tool is not intended to be run as a long-running service. Instead, it is designed to be run for a short period of time while a scan is being invoked and executed in a separate test environment. If this tool is used solely for the scanning purposes, vulnerabilities that may be indicated to exist in the image will not have a chance to be exploited. The user assumes all risks and liability associated with its use.

The `Containerfile.multiuser` image can be used with additional freedom, such as creating additional users. Members of the `dast` group will also have the ability to modify rapidast (such as: adding new policies and writing results in the default location)

### Running on Kubernetes or OpenShift

Helm chart is provided to help with running RapiDAST on Kubernetes or OpenShift.

See [helm/README.md](./helm/README.md)

### Scanners

#### ZAP

ZAP (Zed Attack Proxy) is an open-source DAST tool. It can be used for scanning web applications and API.

See https://www.zaproxy.org/ for more information.

##### Methodology

ZAP needs to be pointed to a list of endpoints to the tested application. Those can be:

* A regular HTLM page
* A REST endpoint
* A GraphQL interface

The GraphQL interface can be provided to RapiDAST via the `graphql` configuration entry. It requires the URL of the GraphQL interface and the GraphQL schema, in order to be scanned. Additional options are available (see the long ZAP configuration template for a list of options).

The other endpoints can be provided via several methods, discussed in the chapters below.

###### an OpenAPI schema

This is the prefered method, to be used whenever possible.
RapiDAST accepts openAPI v2 and v3 schemas (tools are available to convert older schemas into v3). These schemas will describe a list of endpoints, and for each of them, a list of parameters accepted by the application.

###### Build the endpoint list using a spider/crawler

In this method, RapiDAST is given a Web entrypoint. The crawler will download that page, extract a list of URL and recursively crawl all of them. The entire list of URLs found is then provided to the scanner.

There are 2 crawlers available:

- basic spider: the list of URLs will be searched in the HTML tags (e.g.: `<a>`, `<img>`, etc.)
- Ajax spider: this crawler will run a real browser (by default: firefox headless), allowing the dynamic execution of Javascripts from each page found. This method will find URLs generated dynamically.

See the `spider` and `spiderAjax` configuration entries in the long ZAP configuration template for a list of options available.

###### A list of endpoints

A file containing a list of URLs corresponding to endpoints and their parameters.

Example of file:

```
https://example.com/api/v3/groupA/functionA?parameter1=abc&parameter2=123
https://example.com/api/v3/groupB/functionB?parameter1=def&parameter2=456
```

Only GET requests will be scanned

##### ZAP scanner specific options

Below are some configuration tips related to the ZAP scanner.

* Podman only: inject the ZAP container in an existing Pod.
It is possible to gather both RapiDAST and the tested application into the same podman Pod. This might help CI/CD automation & clean-up.
In order to do that, the user must create the Pod prior to running RapiDAST, and indicate its name in the RapiDAST configuration: `scanners.zap.container.parameters.podName`.
However, it is currently necessary to map the host user to UID 1000 / GID 1000 manually during the creation of the Pod using the `--userns=keep-id:uid=1000,gid=1000` option
Example: `podman pod create --userns=keep-id:uid=1000,gid=1000 myApp_Pod`

+ Enable ZAP's Graphical UI (useful for debugging): set `scanners.zap.miscOptions.enableUI: True` (default: False). The runtime type must support it (only `none`)

+ Disable add-on updates: `scanners.zap.miscOptions.updateAddons: False` (default: True): Prior to running, ZAP will update its addons unless this value is `False`

+ Force maximum heap size for the JVM: `scanners.zap.miscOptions.memMaxHeap` (default: ¼ of the RAM): Java's `-Xmx` option

Example:

```yaml
scanners:
    zap:
        container:
            parameters:
                podName: "myApp_Pod"
        miscOptions:
            enableUI: True
            updateAddons: False
            memMaxHeap: "6144m"
```

#### Generic scanner

It is possible to request RapiDAST to run a command in a podman image, using the `generic` plugin.

For example, to run trivy and make it scan itself, and store its output as a result:

```yaml
scanners:
  generic:
    results: "*stdout"

    container:
      type: "podman"
      parameters:
        image: "docker.io/aquasec/trivy"
        command: "image docker.io/aquasec/trivy"
```

The `results` entry works as follow:
* if it is missing or `*stdout`, the output of the command will be chosen and stored as `stdout-report.txt` in the standard result directory
* if it is a directory, it will be recursively copied into the standard result directory
* if it is a file, it will be copied into the standard result directory

__Notes__:
- `command` can be either a list of string, or a single string which will be split using `shlex.split()`
- when using `type: podman`, the results (if different from stdout) must be present on the host after podman has run, which likely means you will need to use the `container.parameters.volumes` entry to share the results between the container and the host.
- See `config/config-template-long.yaml` for additional options.

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

### ZAP's plugins are missing from the host installation

Only when using the host's ZAP (`type: none`)

If you see a message such as `Missing mandatory plugins. Fixing`, or ZAP fails with an error containing the string `The mandatory add-on was not found:`, this is because ZAP deleted the application's plugin.
See https://github.com/zaproxy/zaproxy/issues/7703 for additional information.
RapiDAST works around this bug, but with little inconvenients (slower because it has to fix itself and download all the plugins)

- Verify that the host installation directory is missing its plugins.
e.g., in a MacOS installation, `/Applications/OWASP ZAP.app/Contents/Java/plugin/` will be mostly empty. In particular, no `callhome*.zap` and `network*.zap` file are present.
- Reinstall ZAP, but __DO NOT RUN IT__, as it would delete the plugins. Verify that the directory contains many plugins.
- `chown` the installation files to root, so that when running ZAP, the application running as the user does not have sufficient permission to delete its own plugins

### ZAP crashing with `java.lang.OutOfMemoryError: Java heap space`

ZAP allows the JVM heap to grow up to a quarter of the RAM. The value can be increased using the `scanners.zap.miscOptions.memMaxHeap` configuration entry

```
2023-09-04 08:44:37,782 [main ] INFO  CommandLine - Job openapi started
2023-09-04 08:44:46,985 [main ] INFO  CommandLineBootstrap - OWASP ZAP 2.13.0 terminated.
2023-09-04 08:44:46,985 [main ] ERROR UncaughtExceptionLogger - Exception in thread "main"
java.lang.OutOfMemoryError: Java heap space
        at java.lang.AbstractStringBuilder.<init>(AbstractStringBuilder.java:86) ~[?:?]
        at java.lang.StringBuilder.<init>(StringBuilder.java:116) ~[?:?]
        at com.fasterxml.jackson.core.util.TextBuffer.contentsAsString(TextBuffer.java:487) ~[?:?]
        at com.fasterxml.jackson.core.io.SegmentedStringWriter.getAndClear(SegmentedStringWriter.java:99) ~[?:?]
        at com.fasterxml.jackson.databind.ObjectWriter.writeValueAsString(ObjectWriter.java:1141) ~[?:?]
        at io.swagger.v3.core.util.Json.pretty(Json.java:24) ~[?:?]
        at org.zaproxy.zap.extension.openapi.ExtensionOpenApi.importOpenApiDefinitionV2(ExtensionOpenApi.java:371) ~[?:?]
        at org.zaproxy.zap.extension.openapi.automation.OpenApiJob.runJob(OpenApiJob.java:123) ~[?:?]
        at org.zaproxy.addon.automation.ExtensionAutomation.runPlan(ExtensionAutomation.java:366) ~[?:?]
        at org.zaproxy.addon.automation.ExtensionAutomation.runAutomationFile(ExtensionAutomation.java:507) ~[?:?]
        at org.zaproxy.addon.automation.ExtensionAutomation.execute(ExtensionAutomation.java:621) ~[?:?]
        at org.parosproxy.paros.extension.ExtensionLoader.runCommandLine(ExtensionLoader.java:553) ~[zap-2.13.0.jar:2.13.0]
        at org.parosproxy.paros.control.Control.runCommandLine(Control.java:426) ~[zap-2.13.0.jar:2.13.0]
        at org.zaproxy.zap.CommandLineBootstrap.start(CommandLineBootstrap.java:91) ~[zap-2.13.0.jar:2.13.0]
        at org.zaproxy.zap.ZAP.main(ZAP.java:94) ~[zap-2.13.0.jar:2.13.0]
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
