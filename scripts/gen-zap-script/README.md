# ZAP script generation

This script assists users in generating and loading ZAP scripts to improve and
tailor scanning capabilities. Two types of scripts can be generated: active and
passive. YAML files, called rules, are fed to gen-zap-script to generate and
load ZAP scripts.

Passive rules evaluate regexps in request/response and raise findings in ZAP.
Active rules extend passive rules with the ability to send custom payloads
during the active scanning phase. Those payloads are placed in what ZAP
considers [parameters](https://www.zaproxy.org/docs/desktop/start/features/structparams/).

Loosely inspired from BurpBounty.

## Prerequisites

Python >= 3.8 and jinja2 (`pip install Jinja2`)

## Examples

See `rules/` for rule definition and `python ./cli.py` for help.

Generate a script from a YAML rule and load it in a running ZAP instance:

```
python ./cli.py --load-and-enable --from-yaml ./rules/software_version_revealed.yaml --rapidast-config=<config-file>
```

## Rule files

### Passive rules

```
script_type: passive				# active or passive
script_description: Script Description

# Finding to raise when the searched regexp have a hit
finding_title: Finding Title
finding_description: Finding Description
finding_risk: 1					# 0 (Info), 1 (Low), 2 (Medium), 3 (High)
finding_confidence: 1				# 1 (Low), 2 (Medium), 3 (High)

# Search options
search_in: response.header			# where should the regexp be evaluated
regex:						# list of regexp to evaluate. Modifiers are not allowed
  - 'Server: .*'
  - 'X-Frame-Options: .*'
```

Scripts will raise the finding and quit on the first regexp satisfied.

`search_in` can be one of: `request.method`, `request.url`, `request.header`,
`request.body`, `response.header`, `response.body`.

### Active rules

Active rules file format builds on passive rules:

```
append_payload: true		# append the payloads to the existing parameter value
time_between_requests: 500	# send payloads every 500ms
only_param: .*			# limit to parameters matching this regexp
payload:			# payloads to inject
  - AAA
  - BBB
```

Contrary to passive rules, active rules can only evaluate regular expressions
in the response: `search_in` is limited to `response.header` and
`response.body`.

All payloads are automatically URL-encoded by ZAP.
