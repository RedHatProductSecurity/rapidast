# RapiDAST Developer's Guide

## Install project requirements for development

Install dependencies using the `requirements-dev.txt` file.
```
$ pip install -r requirements-dev.txt
```

## Install pre-commit

pre-commit is being used to ensure that all code committed to the repository meets a certain level of quality and consistency, e.g. regarding style and formatting issues.

The current checks are found in the `.pre-commit-config.yaml` file.

Once pre-commit is installed in the following way, code will be checked automatically when a commit is made.

```
$ pre-commit install
```

## pytest

Add test cases under tests/ when adding a new feature or function if possible. Consult [the pytest homepage](https://docs.pytest.org/en/6.2.x/index.html) as necessary.

Make sure every test case passes whenever any commit is to be made, with the following command:

```
$ pytest
```

## Structure

Its structure is as follow:

* `rapidast.py` does:
    + Loading the main configuration file
    + For each scanner activated by the config, running it

## Adding a scanner

A scanner should:
* be placed in a subdirectory of the `scanners/` directory
* inherit from `RapidastScanner` class
* implement these functions :
    - `__init__(config)` : config being the entire configuration
    - `setup()` : creates whatever needs to be done prior to run
    - `run()` : runs the scan
    - `postprocess()` : stores the results in the global result directory, etc.
    - `cleanup()` : deletes temporary files, shutdown server, etc.
* Set a `className` string for the scanner, which helps RapiDAST to know which class should be implemented
    - Example: `className = "Zap"`


### Authentication factory

A small authentication helper has been provided in the form of decorators.
Scanners who want to authenticate should use it.

To create an authentication decorator, the scanner (e.g.: zap) needs to
first create a decorator associated with the default behaviour (e.g.:
likely either anonymous or error handling)

Example for the ZAP scanner (`scanners.zap`):

```python
from scanners.authentication_factory import generic_authentication_factory

@generic_authentication_factory()
def authentication_factory(self):
  """Default action, called when no corresponding authenticator were found"""
```

Once done, simply register each authentication type, based on
`scanners.*.authentication.type` :

```python
@authentication_factory.register("http_basic")
def authentication_set_http_basic_auth(self):
  """Configure HTTP Basic authentication"""
```

Then calling the `authentication_factory()` function will automatically redirect the call to the correct authentication function.


### Path helper

Because scanners may need to handle path from the "host" view and the "container" view, and translate from one to another, we have created a `path_translator` module to facilitate this.

In practice, this helps to copy files in and out of the container section, or calculate paths inside the container, indepently from the "container" technology. The scanner first needs to setup the mapping correctly, and the rest of the code can work according to the mapping. The mapping usually corresponds to mountpoints, or important directory where the code will need to store/retrieve data.

Example :

```python
from scanners.path_translators import PathMaps
from scanners.path_translators import PathMap

path_map = PathMaps("workdir", "policies", "scripts")
path_map.workdir = PathMap("/on/host/workdir", "/in/container/workdir")

print(f"workdir in container: {path_map.workdir.container_path}")

myfile = "/in/container/workdir/results/myresults.txt"
print(f"myfile on host: {path_map.container_2_host(myfile)}")
```

__NOTES__
+ Important note: there is currently no support for submount : if a mapping is set to `/my/first/mount`, there can not be another map to `/my/first/mount/my/other/mount`
+ The path are immutable: they must be chosen during creation (in the `__init__()` function), and must not be modified afterwards. The parent scanner (e.g.: `Zap`) should define the mount points, and each runtime (e.g.: `ZapPodman`) should fill each map *once*
+ For `type = None` (the scanner will run on the host), then the map must be the same (e.g.: `PathMap("/path/to/dir", "/path/to/dir")`)

### Podman wrapper

A podman scanner can instanciate a `PodmanWrapper` object. This provides functions to prepare the podman command, such as adding volumes, etc.

Example:

```python
# Initialize podman
self.podman = PodmanWrapper(
    app_name=self.config.get("application.shortName"),
    scan_name=self.ident,
    image = self.my_conf("container.parameters.image", default="docker.io/group/application:latest")
)

cli = self.podman.get_complete_cli(self.generic_cli)
self.podman.deploy_to_pod("myPod")
self.podman.add_volume_map("/tmp/result/:/var/results/:Z")
cli = self.podman.get_complete_cli(self.generic_cli)
subprocess.run(self.podman.get_complete_cli(["touch", "/var/results/file"]))
self.podman.delete_yourself():
```

### Integrating the scanner to Defect Dojo

If a scanner is supported by Defect Dojo, the scanner can be configured to export its scan results to Defect Dojo automatically. All it needs to do is to create an optional `data_for_defect_dojo()` method (no parameters).
This can be useful when the scanner exports a file that can be imported into a Defect Dojo test.
This method must return a tuple of 2 values:
* A dictionary containing a subset of values accepted by Defect Dojo's `import-scan` or `reimport-scan` endpoints (see https://demo.defectdojo.org/api/v2/doc/)
* A string corresponding to path of the file containing the scan result, in a format parsable by Defect Dojo.

The dictionary must not:
* contain the `file` entry, as it is done via the tuple's 2nd value

The dictionary must:
* Contain enough information to let Defect Dojo import the file (e.g.: provide a test identifier for re-import, or at least a `product_name` + `engagement_name` so that Defect Dojo can create a test on its own)
* Provide the scan `scan_type` corresponding to the result file (e.g.: `ZAP Scan` for ZAP), as well as all other mandatory field (`verified` and `active`)

Note: simply return the `(None, None)` tuple to abort the operation.

## The configuration model

The "RapidastConfigModel" object is used to load and merge YAML configuration files. This provides several benefits:
- It is possible to get the values without having to manually walk through the configuration tree, using code such as `config.get("scanners.zap.apis.apiUrl", default="")`.
- There is no need to try/except the code, or verify the existence of a key before descending. If a key (or path to the key) does not exist, `default` will be returned.
- Similarly `config.set("scanners.zap.apis.apiUrl", "http://example.com/")` will create the path if needed, without raising an exception.

To merge a dictionary into a configuration, use `config.merge(merge: dict, preserve: bool, root: path)`:
    + from `config[<root>]` onwards, the configuration will copy values from `merge`, descending on keys of the same name
    + in case of collision (2 keys with same name, but at most only 1 value is a dictionary), the original configuration will be preserved only if `preserve=True` was set

Developers are encouraged to use this configuration model, although the configuration can be directly accessed via the underlying `config.config` dict


 _WARNINGS and LIMITATIONS_:
- Currently, the model does not support lists ( e.g.: `-` or `[]` in YAML), i.e.: `config.get("path.to.list[0]")` does not work. Avoid those if possible, otherwise get a reference to the list (i.e.: `config.get("path.to.list")`) , and manipulate it in python directly.

### Default value

Currently, the default value of a config entry is being set in the code like `<configModel>.get("path.to.entry", default="<sane-default>")`.
When looking up an entry, the developer has the responsibility to make a "good default" in case the entry does not exist in the configuration.

__Note/Warning__: This has the downside of possibly having different default values for the same entry, which may be problematic (also, we need to be careful when we want to change the default).


### Automatically updating the configuration schema

There may be time during which development requires incompatible changes in the configuration schema, such as renaming, deleting or moving of an entry. An "incompatible change" means any change in the code that would prevent a previously working configuration file from working correctly. This must be avoided. For example, adding new entries should not impact previous configuration __provided that default values are mimicking previous behavior__. Otherwise, this creates an issue while handling users' current configuration which hasn't been updated yet.

RapiDAST works around the issue in the following way.
Every time there is an incompatible change:
1) In `configmodel/converter.py` :
    a) increase `CURR_CONFIG_VERSION` by 1 (in the following text, the old number is referred to as `$X`, and, respectively the updated version number as `${X+1}` )
    b) write a converter function, decorated with `@convert_configmodel.register(${X})`
       This function must take a configuration schema version ${X}, and must return a copy, updated to ${X+1}
2) Keep a copy of `config-template-long.yaml`, named `config/older-schemas/v${X}.yaml`. This is just for safekeeping, so that we don't need to go through git history to retrieve previous schemas.
3) Make the changes in the `config/config-template*.yaml` files. Including:
    a) `config.configVersion` must be set to ${X+1}
    b) all the changes are applied (`config-template-long.yaml` should contain all changes, and `config-template.yaml` only the user-friendly ones
4) Provide explanation in the corresponding commit

RapiDAST, when loading the configuration from file, will update the schema, version by version, by chaining all the converting functions one by one until `CURR_CONFIG_VERSION` is reached. e.g.: from 2 to 3, then 3 to 4, 4 to 5, etc.

Note: it is possible for a converter function to warn the user, if necessary. As a last resort, if there is no conversion possible, it is also possible to output an error **BUT** the error should clearly express a methodology to manually update the configuration to the newest version
