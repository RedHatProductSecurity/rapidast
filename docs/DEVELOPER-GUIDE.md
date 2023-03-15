# RapiDAST Developer's Guide

## Adding a scanner

A scanner should:
* be placed in a subdirectory of the `scanners/` directory
* inherit from `RapidastScanner` class
* implement these functions :
    - `__init__(config)` : config being the entire configuration
    - `setup()` : create whatever needs to be done prior to run
    - `run()` : runs the scan
    - `postprocess()` : stores the results in the global result directory, etc.
    - `cleanup()` : delete temporary files, shutdown server, etc.
* implement a `className` string, which helps RapiDAST to know which class should be implemented
    - Example: `className = "Zap"`


## The configuration model

The YAML config files are loaded and merged together using a "RapidastConfigModel" object. This facilitates:
- Getting the values without having to manually walk through it. e.g.: `config.get("scanners.zap.apis.apiUrl", default="")`
- There is no need to try/except the code, or verify the existence of a key before descending. If a key (or path to the key) does not exist, `default` will be returned
- Similarly `config.set("scanners.zap.apis.apiUrl", "http://example.com/")` will create the path if needed, without raising exception
- To merge a dictionary into a configuration, use `config.merge(merge: dict, preserve: bool, root: path)`:
    + from `config[<root>]` onwards, the configuration will copy values from `merge`, descending on keys of the same name
    + in case of collision (2 keys with same name, but at most only 1 value is a dictionary), the original configuration will be preserved only if `preserve=True` was set
- Developers are encouraged to use this configuration model, although the configuration can be directly accessed via the underlying `config.config` dict


 _WARNINGS and LIMITATIONS_:
- Currently, the model does not support lists ( e.g.: `-` or `[]` in YAML), i.e.: `config.get("path.to.list[0]")` does not work. Avoid those if possible, otherwise get a reference to the list (i.e.: `config.get("path.to.list")`) , and manipulate it in python directly.

### default vs. user-defined

Currently, the default values are stored in the code itself. This is done using `<configModel>.get("path.to.entry", default="<sane-default>")`
When looking up for an entry, the developer has the responsibity to make a "good default" in case the entry does not exist in the configuration.

__Note/Warning__: This has the downside of possibly having different default values for the same entry, which may be problematic (also, we need to be careful when we want to change the default).


### Updating the configuration schema

There may be time during which development requires incompatible changes in the configuration schema. Such as renaming, deleting or moving of an entry.
This creates issues with user configuration, which are not supposed to be updated (or at least as little as possible).

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

An "incompatible change" is any change in the code that would prevent a previously working configuration file to work correctly. For example : adding new entries should not impact previous configuration __provided that default values are mimicking previous behavior__

RapiDAST, when loading the configuration from file, will update the schema, version by version, by chaining all the converting functions one by one until `CURR_CONFIG_VERSION` is reached. e.g.: from 2 to 3, then 3 to 4, 4 to 5, etc.

Note: it is possible for an converter function to warn the user, if necessary. As a last resort, if there is no conversion possible, it is also possible to output an error **BUT** the error should clearly express a methodology to manually update the configuration to the newest version
