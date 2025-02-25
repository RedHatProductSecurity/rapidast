# Exporting to DefectDojo

RapiDAST supports integration with OWASP DefectDojo which is an open source vulnerability management tool.

## Preamble: creating DefectDojo user

RapiDAST needs to be able to authenticate to your DefectDojo instance. However, ideally, it should have the minimum set of permissions, such that it will not be allowed to modify products other than the one(s) it is supposed to.

In order to do that:

- create a user without any global role
- add that user as a "writer" for the product(s) it is supposed to scan

Then the product, as well as an engagement for that product, must be created in your DefectDojo instance. It would not be advised to give the RapiDAST user an "admin" role and simply set `auto_create_context` to True, as it would be both insecure and accident prone (a typo in the product name would let RapiDAST create a new product)

## Exporting to Defect Dojo

RapiDAST will send the results directly to a DefectDojo service. This is a typical configuration:

```yaml
config:
  # Defect dojo configuration
  defectDojo:
    url: "https://mydefectdojo.example.com/"
    ssl: [True | False | "/path/to/CA"]
    authorization:
      username: "rapidast_productname"
      password: "password"
      # alternatively, a `token` entry can be set in place of username/password
```

The `ssl` parameter is provided as the Python Requests module's `verify` parameter. It can be either:

- True: SSL verification is mandatory, against the default CA bundle
- False: SSL verification is not mandatory (but prints a warning if it fails)
- /path/to/CA: a bundle of CAs to verify from

Alternatively, the `REQUESTS_CA_BUNDLE` environment variable can be used to select a CA bundle file. If nothing is provided, the default value will be `True`

You can either authenticate using a username/password combination, or a token (make sure it is not expired). In either case, you can use the `_from_var` method described in the previous chapter to avoid hardcoding the value in the configuration.

## Configuration of exported data

The data exported follows the Defectdojo methodology of "Product → Engagement → Test" : a test, such as a ZAP scan, belongs to an engagement for a product.
Its configuration is made under the `scanners.<scanner>.defectDojoExport.parameters` configuration entries. As a baseline, parameters from the Defectdojo `import-scan` and `reimport-scan` are accepted.

For each scan, the logic applied is the following, in order:

- If a test ID is provided (parameter `test`), this scan will replace the previous one (a "reimport" in Defectdojo)
- If an engagement ID is provided (parameter `engagement`), this scan will be added as a new test in that existing engagement
- If an engagement and a product are given by name (`engagement_name` and `product_name` parameters), this scan will be added for that given engagement for the given product

In each `defectDojoExport.parameters`, some defaults parameters are applied:

- `product_name`, in order (the first non empty value found):
  - `application.productName`
  - `application.shortName` (this name should not contain non-printable characters, such as spaces)
- `engagement_name` defaults to `RapiDAST-<product name>-<date>`
- `scan_type` : filled by the scanner
- `active`: `True`
- `verified`: `False`

As a reminder: values from `general` are applied to each scanner.

Here is an example:

```yaml
scanners:
  zap:
    defectDojoExport:
      parameters:
        product_name: "My Product"
        engagement_name: "RapiDAST" # or engagement: <engagement_id>
        #test: <test_id>
```

See <https://documentation.defectdojo.com/integrations/importing/#api> for more information.
