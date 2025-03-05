# RapiDAST

![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/redhatproductsecurity/rapidast/run-tests.yml?branch=development&logo=github&label=CI) ![GitHub License](https://img.shields.io/github/license/redhatproductsecurity/rapidast)

RapiDAST (Rapid DAST) is an open-source security testing tool that automates DAST ([Dynamic Application Security Testing](https://owasp.org/www-project-devsecops-guideline/latest/02b-Dynamic-Application-Security-Testing)) and streamlines the integration of security testing into development workflows. It is designed to help Developers and/or QA engineers rapidly and effectively identify low-hanging security vulnerabilities in your applications, ideally in CI/CD pipelines. RapiDAST is for organizations implementing DevSecOps with a shift-left approach.

RapiDAST provides:

- Automated HTTP/API security scanning leveraging ZAP
- Automated LLM AI scanning leveraging Garak
- Kubernetes operator scanning leveraging OOBTKUBE
- Automated vulnerability scanning using Nessus (requires a Nessus instance)
- Command-line execution with yaml configuration, suitable for integration in [CI/CD pipelines](./examples/)
- Ability to run automated DAST scanning with pre-built or custom container images
- HTML, JSON and XML report generation
- Integration with Google Cloud Storage and [OWASP DefectDojo](https://owasp.org/www-project-defectdojo/)

RapiDAST is for testing purposes, and should not be used on production systems.

## Deprecation Notice

**Podman Mode Deprecation**
The `podman` execution environment is deprecated and will be removed in version **2.12**

If you are using `podman` fpr the `container.type` option, please migrate to `none` before updating to version 2.12.

## Quickstart

Quickly setup RapiDAST to scan a target application. See [Workflow](#workflow) for more information.

1. Create a minimal config file for the target application, see [Configuration](#configuration) section for details
2. Run RapiDAST with the config file, either in a container or from source code

### OS Support

Linux and MacOS are both supported, however running RapiDAST in a container is currently only supported on Linux. See [MacOS Configuration](#macos) section for more details.

### Run in container (Linux only)

Run the pre-built [rapidast container image](https://quay.io/repository/redhatproductsecurity/rapidast), which includes scanners like [ZAP]. Not compatible with config files using `general.container.type` set to `podman`.

**Prerequisites**:

- `docker` / `podman` (>= v3.0.1)

**Run**:

```sh
$ podman run -v ./config.yaml:/opt/rapidast/config/config.yaml:Z quay.io/redhatproductsecurity/rapidast:latest
```

**Note**:

- Sample config is very minimal and has no [Authentication](#authentication) enabled
- The `:Z` option is only necessary on RHEL/CentOS/Fedora systems with SELinux enabled
- To retrieve scan results, add a volume mount like `-v ./results/:/opt/rapidast/results/:Z`. The permissions of the `./results/` directory may need to be modified first with a command like `chmod o+w ./results/` to be writeable by the rapidast user in the container.

### Run from source

Install dependencies and run RapiDAST directly on a host machine. Unless using the config setting of `general.container.type: podman`, scanners like [ZAP] are expected to be installed on the host system.

**Prerequisites**:

- `python` >= 3.6.8 (3.7 for MacOS/Darwin)
- `podman` >= 3.0.1
  - required when you want to run scanners from their container images, rather than installing them to your host.
- See `requirements.txt` for a list of required python libraries

**Setup**:

Clone the repository.

```sh
$ git clone https://github.com/RedHatProductSecurity/rapidast.git
$ cd rapidast
```

Create a virtual environment.

```sh
$ python3 -m venv venv
$ source venv/bin/activate
```

Install the project requirements.

```sh
(venv) $ pip install -U pip
(venv) $ pip install -r requirements.txt
```

**Run**:

Run RapiDAST script:

```sh
$ ./rapidast.py --config <path/to/config.yml>
```

**Note**:

- Example minimum config expects scanners like [ZAP] to be available on the host, and will fail if not found. See [Execution Environments](#choosing-the-execution-environment) section for more info
- Results will be written to the `./results/` directory

## Workflow

This section summarize the basic workflow as follows:

1. Create a configuration file for testing the application. See the [configuration](#configuration) section below for more information.
    - Optionally, an [environment file](#advanced-configuration) may be added, e.g., to separate the secrets from the configuration file.
2. Run RapiDAST and get the results.
    - First run with passive scanning only, which can save time at the initial scanning phase. There are various situations that can cause an issue, not only from scanning set up but also from your application or test environment. Active scanning takes a long time in general.
    - Once passive Scanning has run successfully, run another scan with active scanning enabled in the configuration file.

See [here](./examples/) for examples on how to run RapiDAST in various CI/CD pipelines.

## Configuration

The configuration file is presented as YAML, and contains several main entries:

- `config` : contains `configVersion` which tells RapiDAST how to consume the config file
- `application` : contains data relative to the application being scanned : name, etc.
- `general` : contains data that will be used by all the scanners, such as proxy configuration, etc.
  - Each scanner can override an entry from `general` by creating an entry with the same name
- `scanners` : list of scanners, and their configuration

See templates in the [config](./config/) directory for rapidast configuration examples.

- `config-template-zap-tiny.yaml` : describes a bare minimum configuration, without authentication options.
- `config-template-zap-simple.yaml` : describes a generic/minimal use of the ZAP scanner (i.e.: the minimum set of option to get a ZAP scan from RapiDAST)
- `config-template-zap-mac.yaml` : describes a minimal use of the ZAP scanner on a Apple Mac environment
- `config-template-zap-long.yaml` : describes a more extensive use of ZAP (all configuration options are presented)
- `config-template-multi-scan.yaml` : describes how to combine multiple scanners in a single configuration
- `config-template-generic-scan.yaml` : describes the use of the generic scanner
- `config-template-garak.yaml` : describes the use of the Garak LLM AI scanner

See [here](./examples/) for examples on how to run RapiDAST in various CI/CD pipelines.

### Basic Example

Example bare minimum [config file](./config/config-template-zap-tiny.yaml), without any [Authentication](#authentication) options, and passive scanning only:

```yaml
config:
  configVersion: 5

application:
  shortName: "example-1.0"
  url: "https://example.com" # root URL of the application

scanners:
  zap:
    apiScan:
      apis:
        apiUrl: "https://example.com/api/v1/swagger.json" # URL to application openAPI spec
```

### Authentication

Authentication is configured in the `general` entry, as it can be applied to multiple scanning options. Currently, Authentication is applied to [ZAP] scanning only. In the long term it may be applied to other scanning configurations.

Supported options:

- No authentication:
The scanners will communicate anonymously with the application

- OAuth2 using a Refresh Token:
This method describes required parameters needed to retrieve an access token, using a refresh token as a secret.

  - authentication type : `oauth2_rtoken`
  - parameters :
    - `token_endpoint`: the URL to which send the refresh token
    - `client_id` : the client ID
    - `rtoken_from_var`: for practical reasons, the refresh token is provided using environment variables. This entry describes the name of the variable containing the secret refresh token
    - `preauth`: Pre-generate a token and force ZAP to use it throughout the session (the session token will not be refreshed after it's expired). Default: False. This is only useful for scans sufficiently short that it will be finished before the token expires

- HTTP Basic:
This method describes the HTTP Basic Authorization Header. The username and password must be provided in plaintext and will be encoded by the scanners

  - authentication type: `http_basic`
  - parameters:
    - `username`
    - `password`

- HTTP Header:
This method describes the HTTP generic header. The name and value must be provided in plaintext.
  - authentication type: `http_header`
  - parameters:
    - `name`: the header name added to every request. By default is `Authorization`
    - `value` or `value_from_var` (the environment variable with the secret)

- Cookie Authentication:
This method describes authentication via Cookie header. The cookie name and value must be provided in plaintext.

  - authentication type: `cookie`
  - parameters:
    - `name`
    - `value`

- Browser authentication method
This method uses firefox in the background to load a login page and fill in username/password, and will retrieve and set the session cookies accordingly.
  - authentication type: `browser`
  - parameters:
    - `username`
    - `password`
    - `loginPageUrl`: the URL to the login page (either the full URL, or relative to the `application.url` value)
    - `loginPageWait`: The number of seconds to wait after submitting the login form before the browser is closed. (default: 2)
    - `verifyUrl`: a URL that "proves" the user is authenticated (either the full URL, or relative to the `application.url` value). This URL must return a success if the user is correctly authenticated, and an error otherwise.
    - `loggedInRegex`: Regex pattern used to identify Logged in messages (default: `\\Q 200 OK\\`)
    - `loggedOutRegex`: Regex pattern used to identify Logged Out messages (default: `\\Q 403 Forbidden\\`)

### MacOS

RapiDAST supports executing scanners like [ZAP] on the MacOS host directly only.

To run RapiDAST on MacOS(See the Configuration section below for more details on configuration):

- Set `general.container.type: "none"` or `scanners.zap.container.type: "none"` in the configuration.
- Configure `scanners.zap.container.parameters.executable` to the installation path of the `zap.sh` command, because it is not available in the PATH. Usually, its path is `/Applications/ZAP.app/Contents/Java/zap.sh` on MacOS.

Example:

```yaml
scanners:
  zap:
    container:
      type: none
      parameters:
        executable: "/Applications/ZAP.app/Contents/Java/zap.sh"
```

### Advanced configuration

You may not want to directly have configuration values inside the configuration. Typically: either the entry is a secret (such as a password), but the configuration needs to be public, or the entry needs to be dynamically generated (e.g.: a cookie, a uniquely generated URL, etc.) at the time of running RapiDAST, and it's an inconvenient to always having to modify the configuration file for each run.

To avoid this, RapiDAST proposes 2 ways to provide a value for a given configuration entry. For example, to provide a value for the entry `general.authentication.parameters.rtoken`, you can either (in order of priority):

- Create an entry in the configuration file (this is the usual method)
- Create an entry in the configuration file pointing to the environment variable that actually contains the data, by appending `_from_var` to the entry name: `general.authentication.parameters.rtoken_from_var=RTOKEN` (in this example, the token value is provided by the `$RTOKEN` environment variable)

#### Running several instance of a scanner

It is possible to run a scanner several times with different configurations. This is done by adding a different identifier to each scan, by appending `_<id>` to the scanner name.

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

### Exporting data to external services

#### Exporting to Google Cloud Storage

This simply stores the data as a compressed tarball in a Google Cloud Storage bucket.

```yaml
config:
  # Defect dojo configuration
  googleCloudStorage:
    keyFile: "/path/to/GCS/key"                           # optional: path to the GCS key file (alternatively: use GOOGLE_APPLICATION_CREDENTIALS)
    bucketName: "<name-of-GCS-bucket-to-export-to>"       # Mandatory
    directory: "<override-of-default-directory>"          # Optional directory where the credentials have write access, defaults to `RapiDAST-<product>`
```

Once this is set, scan results will be exported to the bucket automatically. The tarball file will include:

 1. metadata.json - the file that contains scan_type, uuid and import_data(could be changed later. Currently this comes from the previous DefectDojo integration feature)
 2. scans - the directory that contains scan results

#### Exporting to DefectDojo

RapiDAST supports integration with OWASP DefectDojo which is an open source vulnerability management tool. See [here](./docs/DEFECT_DOJO.md) for more information.

## Execution

Once you have created a configuration file, you can run a scan with it.

```sh
$ ./rapidast.py --config "<your-config.yaml>"
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
                        useful for debugging purposes).
```

### Choosing the execution environment

Set `general.container.type` to select an environment (default: `none`)

- `none` (default):
  - Run a RapiDAST scan with scanners that are installed on the same host OR run RapiDAST in a container (scanners are to be installed in the same container image)
  - __Warning__: without a container layer, RapiDAST may have to modify the host's file system, such as the tools configuration to fit its needs. For example: the ZAP plugin has to copy the policy file used in ZAP's user config directory (`~/.ZAP`)

- `podman` (this mode is deprecated and will be **removed** in version **2.12**):
  - Run scanners as separate containers using `podman`
  - RapiDAST must not run inside a container
  - Select the image to load from `scanner.<name>.container.image` (sensible default are provided for each scanner)

It is also possible to set the container type for each scanner differently by setting `scanners.<name>.container.type` under a certain scanner configuration. Then the scanner will run from its image, regardless of the `general.container.type` value.

## Build a RapiDAST image

If you want to build your own RapiDAST image, run the following command.

```sh
$ podman build . -f containerize/Containerfile -t <image-tag>
```

Disclaimer: This tool is not intended to be run as a long-running service. Instead, it is designed to be run for a short period of time while a scan is being invoked and executed in a separate test environment. If this tool is used solely for the scanning purposes, vulnerabilities that may be indicated to exist in the image will not have a chance to be exploited. The user assumes all risks and liability associated with its use.

### Running on Kubernetes or OpenShift

Helm chart is provided to help with running RapiDAST on Kubernetes or OpenShift.

See [helm/README.md](./helm/README.md)

### Scanners

#### ZAP

ZAP (Zed Attack Proxy) is an open-source DAST tool. It can be used for scanning web applications and API.

See <https://www.zaproxy.org/> for more information.

##### Methodology

ZAP needs to be pointed to a list of endpoints to the tested application. Those can be:

- A regular HTML page
- A REST endpoint
- A GraphQL interface

The GraphQL interface can be provided to RapiDAST via the `graphql` configuration entry. It requires the URL of the GraphQL interface and the GraphQL schema(if available), in order to be scanned. Additional options are available. See the `config-template-zap-long.yaml` configuration template file for a list of options.

The other endpoints can be provided via several methods, discussed in the chapters below.

###### an OpenAPI schema

This is the prefered method, to be used whenever possible.
RapiDAST accepts OpenAPI v2(formerly known as Swagger) and v3 schemas. These schemas will describe a list of endpoints, and for each of them, a list of parameters accepted by the application.

###### Build the endpoint list using a spider/crawler

In this method, RapiDAST is given a Web entrypoint. The crawler will download that page, extract a list of URLs and recursively crawl all of them. The entire list of URLs found is then provided to the scanner.

There are two crawlers available:

- Basic spider: the list of URLs will be searched in the HTML tags (e.g.: `<a>`, `<img>`, etc.)
- Ajax spider: this crawler will run a real browser (by default: firefox headless), allowing the dynamic execution of Javascripts from each page found. This method will find URLs generated dynamically.

See the `spider` and `spiderAjax` configuration entries in the `config-template-zap-long.yaml` configuration template file for a list of options available.

###### A list of endpoints

A file containing a list of URLs corresponding to endpoints and their parameters.

Example of file:

```
https://example.com/api/v3/groupA/functionA?parameter1=abc&parameter2=123
https://example.com/api/v3/groupB/functionB?parameter1=def&parameter2=456
```

Only GET requests will be scanned.

##### ZAP scanner specific options

Below are some configuration options that are worth noting, when running a RapiDAST scan with the ZAP scanner.

- (`*.container.type: podman` only) Inject the ZAP container in an existing Pod:

It is possible to gather both RapiDAST and the tested application into the same podman Pod and run a scan against the application. This might help CI/CD automation & clean-up.
In order to do that, the user must create the Pod prior to running RapiDAST, and indicate its name in the RapiDAST configuration: `scanners.zap.container.parameters.podName`.
However, it is currently necessary to map the host user to UID 1000 / GID 1000 manually during the creation of the Pod using the `--userns=keep-id:uid=1000,gid=1000` option
Example: `podman pod create --userns=keep-id:uid=1000,gid=1000 myApp_Pod`

- (when running scans on the desktop with the `*.container.type: none` configuration only) Enable ZAP's Graphical UI:

This is useful for debugging.  Set `scanners.zap.miscOptions.enableUI: True` (default: False).  Then, the ZAP desktop will run with GUI on your host and show the progress of scanning.

- Enable add-on updates:

Set `scanners.zap.miscOptions.updateAddons: True` (default: False). ZAP will first update its addons and then run the scan.

- Install additional addons:

Set `scanners.zap.miscOptions.additionalAddons: "comma,separated,list,of,addons"` (default: []). Prior to running a scan, ZAP will install a given list of addons. The list can be provided either as a YAML list, or a string of the addons, separated by a comma.

- Force maximum heap size for the JVM:

Set `scanners.zap.miscOptions.memMaxHeap` (default: ¼ of the RAM), similarly to Java's `-Xmx` option.

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

- To use ZAP's '-config' option:

Set `scanners.zap.miscOptions.overrideConfigs` with the same value as you would run with ZAP's '-config' option. It allows RapiDAST to run additional '-config' options when it invokes the ZAP cli command. This can be useful to set a value for Path parameters of the OpenAPI specification. The following example will allow RapiDAST to send the 'default' value to the `{namespace}` parameter in your OpenAPI file.

Example:

```yaml
scanners:
  zap:
    overrideConfigs:
      - formhandler.fields.field(0).fieldId=namespace
      - formhandler.fields.field(0).value=default
```

#### Nessus

Nessus is a vulnerability scanner developed by Tenable, Inc. It helps organizations identify and address security vulnerabilities across various systems, devices, and applications.

The following is an example to launch a scan:

```yaml
scanners:
  nessus:
    server:
      url: https://nessus-example.com/ # URL of Nessus instance
      username: foo # OR username_from_var: NESSUS_USER
      password: bar # OR password_from_var: NESSUS_PASSWORD
    scan:
      name: test-scan # name of new scan to create
      folder: test-folder # name of folder in to contain scan
      policy: "py-test" # policy used for scan
      # timeout: 600 # timeout in seconds to complete scan
      targets:
      - 127.0.0.1
```

#### Garak

Garak is an LLM AI scanner developed by NVIDIA. See https://github.com/NVIDIA/garak for more information.

The following is an example to launch a scan:
```yaml
scanners:
  garak:
    parameters:
      plugins:
        model_type: huggingface
        model_name: gpt2
```

#### Generic scanner

In addition to the scanners mentioned above, RapiDAST can run any other scanning tools. It is possible to request RapiDAST to run a command and process stdout results, using the `generic` plugin. One use case is to run your own tools or scripts and export the results to Google Cloud Storage.

The following is an example to run a command or a tool in the host where a RapiDAST scan runs:

```yaml
scanners:
  generic:
    results: "*stdout"

    # this config is used when container.type is not 'podman'
    toolDir: scanners/generic/tools
    inline: "echo 'any scan'"
```

(an experimental feature) The following example is to scan a Kubernetes Operator's controller code for a command injection attack:

```yaml
scanners:
  generic:
    results: "*stdout"

    # this config is used when container.type is not 'podman'
    # toolDir: scanners/generic/tools
    inline: "python3 oobtkube.py -d 300 -p <port> -i <ipaddr> -f <cr_example>.yaml"
```

The following is another example to run a [Trivy](https://github.com/aquasecurity/trivy) scan using the container image:

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

- if it is missing or `*stdout`, the output of the command will be chosen and stored as `stdout-report.txt` in the result directory
- if it is a directory, it will be recursively copied into the result directory
- if it is a file, it will be copied into the result directory

**Notes**:

- `command` can be either a list of string, or a single string which will be split using `shlex.split()` - when using `*.container.type: podman`, the results (if different from stdout) must be present on the host after podman has run, which likely means you will need to use the `container.parameters.volumes` entry to share the results between the container and the host.
- See `config/config-template-generic-scan.yaml` for additional options.

## Troubleshooting

### Hitting docker.io rate limits

If you are unable to pull/update an image from docker.io due to rate-limit errors, authenticate to your Docker Hub account.

### "Error getting access token" using OAuth2

Possible pitfalls :

- Make sure that the parameters are correct (`client_id`, `token_endpoint`, `rtoken_var_name`) and that the refresh token is provided (via environment variable), and is valid
- Make sure you do not have an environment variable in your current environment that overrides what is set in the `envFile`

### Issues with the ZAP scanner

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

This happens only when using the host's ZAP (with the `*.container.type: none` option).

If you see a message such as `Missing mandatory plugins. Fixing`, or ZAP fails with an error containing the string `The mandatory add-on was not found:`, this is because ZAP deleted the application's plugin.
See <https://github.com/zaproxy/zaproxy/issues/7703> for additional information.
RapiDAST works around this bug, but with little inconvenients (slower because it has to fix itself and download all the plugins)

- Verify that the host installation directory is missing its plugins.
e.g., in a MacOS installation, `/Applications/ZAP.app/Contents/Java/plugin/` will be mostly empty. In particular, no `callhome*.zap` and `network*.zap` file are present.
- Reinstall ZAP, but *DO NOT RUN IT*, as it would delete the plugins. Verify that the directory contains many plugins.
- `chown` the installation files to root, so that when running ZAP, the application running as the user does not have sufficient permission to delete its own plugins

### ZAP crashing with `java.lang.OutOfMemoryError: Java heap space`

ZAP allows the JVM heap to grow up to a quarter of the RAM. The value can be increased using the `scanners.zap.miscOptions.memMaxHeap` configuration entry

```sh
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

### ZAP crashed while parsing the OpenAPI due to its size

```sh
2024-02-29 19:35:24,526 [main ] INFO  CommandLine - Job openapi started
2024-02-29 19:35:25,576 [main ] WARN  DeserializationUtils - Error snake-parsing yaml content
io.swagger.v3.parser.util.DeserializationUtils$SnakeException: Exception safe-checking yaml content  (maxDepth 2000, maxYamlAliasesForCollections 2147483647)
    at io.swagger.v3.parser.util.DeserializationUtils$CustomSnakeYamlConstructor.getSingleData(DeserializationUtils.java:483) ~[openapi-beta-37.zap:?]
    at org.yaml.snakeyaml.Yaml.loadFromReader(Yaml.java:493) ~[openapi-beta-37.zap:?]
.........

2024-02-29 19:35:25,639 [main ] ERROR DeserializationUtils - Error parsing content
com.fasterxml.jackson.dataformat.yaml.JacksonYAMLParseException: The incoming YAML document exceeds the limit: 3145728 code points.
 at [Source: (StringReader); line: 49813, column: 50]
..........

2024-02-29 19:35:25,702 [main ] WARN  OpenAPIV3Parser - Exception while parsing:
com.fasterxml.jackson.dataformat.yaml.JacksonYAMLParseException: The incoming YAML document exceeds the limit: 3145728 code points.
 at [Source: (StringReader); line: 49813, column: 50]
```

Solutions:

- If you are using a Swagger v2 definition, try converting it to v3 (OpenAPI)
- Set a `maxYamlCodePoints` Java proprety with a big value, which can be passed using environment variables (via the `config.environ.envFile` config entry): `_JAVA_OPTIONS=-DmaxYamlCodePoints=99999999`

### ZAP's Ajax Spider failing

#### Insufficient Resources

Zap's Ajax Spider makes use of a lot of resources, in particular:

- Shared Memory (`/dev/shm`)
- processes

If you see evidence of Firefox crashing, either via in the `zap.log` files stored in `session.tar.gz` file (see below for examples of such evidence), or logged by an external crash report (such as `abrtd` for example).

`zap.log` hints for Firefox crashing:

```sh
2024-07-04 11:21:32,061 [ZAP-AjaxSpiderAuto] WARN  SpiderThread - Failed to start browser firefox-headless
com.google.inject.ProvisionException: Unable to provision, see the following errors:

1) [Guice/ErrorInCustomProvider]: SessionNotCreatedException: Could not start a new session. Response code 500. Message: Failed to decode response from marionette
```

Or the following:

```sh
2024-07-04 12:23:28,027 [ZAP-AjaxSpiderAuto] ERROR UncaughtExceptionLogger - Exception in thread "ZAP-AjaxSpiderAuto"
java.lang.OutOfMemoryError: unable to create native thread: possibly out of memory or process/resource limits reached
```

This issue may also be apparent *outside* of the spider, in particular, the following error being printed on the RapiDAST output is likely an evidence that the maximum number of concurrent thread is currently reached:

```sh
Failed to start thread "Unknown thread" - pthread_create failed (EAGAIN) for attributes: stacksize: 1024k, guardsize: 0k, detached.
```

Solutions:

- Selenium, used to control Firefox, uses shared memory (`/dev/shm/`). When using the RapiDAST image or the ZAP image, the user needs to make sure that sufficient space is available in `/dev/shm/` (in podman, by default, its size is 64MB). A size of 2G is the recommended value by the Selenium community. In podman for example, the option would be `--shm-size=2g`.
- Zap and Firefox can create a huge numbers of threads. Some container engines will default to 2048 concurrent pids, which is not sufficient for the Ajax Spider. Whenever possible, RapiDAST will check if that limit was reached, after the scan is finished, and prints a warning if this happened. In podman, increasing the maximum number of concurrent pids is done via the `--pids-limit=-1` option to prevent any limits.

### Podman errors

#### subuid/subgid are not enabled

If you see one of those errors:

```sh
Error: copying system image from manifest list: writing blob: adding layer with blob "sha256:82aabceedc2fbf89030cbb4ff98215b70d9ae35c780ade6c784d9b447b1109ed": processing tar file(potentially insufficient UIDs or GIDs available in user namespace (requested 0:42 for /etc/gshadow): Check /etc/subuid and /etc/subgid if configured locally and run "podman system migrate": lchown /etc/gshadow: invalid argument): exit status 1
```

 -or-

```sh
Error: parsing id map value "-1000": strconv.ParseUint: parsing "-1000": invalid syntax
```

Podman, in rootless mode (running as a regular user), needs subuid/subgit to be enabled: [rootless mode](https://docs.podman.io/en/latest/markdown/podman.1.html#rootless-mode)

## Caveats

- Currently, RapiDAST does not clean up the temporary data when there is an error. The data may include:
  - a `/tmp/rapidast_*/` directory
  - a podman container which name starts with `rapidast_`

This is to help with debugging the error. Once confirmed, it is necessary to manually remove them.

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/RedHatProductSecurity/rapidast/issues) on GitHub.

## Contributing

Contribution to the project is more than welcome.

See [CONTRIBUTING.md](./CONTRIBUTING.md)

[ZAP]: #ZAP
