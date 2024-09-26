import argparse
import json
import logging


def remove_recursive_refs(openapi_dict):
    def remove_recursive_refs_from_schema(schema, path):
        if isinstance(schema, dict):
            if "$ref" in schema and schema["$ref"] == path:
                logging.info(f"Removing recursive $ref in schema at path: {path}")
                del schema["$ref"]
            for _, value in list(schema.items()):
                if isinstance(value, dict):
                    remove_recursive_refs_from_schema(value, path)
                elif isinstance(value, list):
                    for item in value:
                        remove_recursive_refs_from_schema(item, path)

    def process_components(components):
        if "schemas" in components:
            for schema_name, schema in components["schemas"].items():
                path = f"#/components/schemas/{schema_name}"
                logging.debug(f"Processing schema: {schema_name}, path: {path}")
                remove_recursive_refs_from_schema(schema, path)
        if "parameters" in components:
            for param_name, param in components["parameters"].items():
                if "schema" in param:
                    path = f"#/components/parameters/{param_name}"
                    logging.debug(f"Processing parameter: {param_name}")
                    remove_recursive_refs_from_schema(param["schema"], path)

    if "components" in openapi_dict:
        logging.debug("Processing components section")
        process_components(openapi_dict["components"])

    return openapi_dict


def main(input_file, output_file, debug):
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    logging.debug(f"Reading OpenAPI JSON from file: {input_file}")
    with open(input_file, "r", encoding="utf-8") as f:
        openapi_dict = json.load(f)

    logging.debug("Start removing recursive $ref fields")
    cleaned_openapi_dict = remove_recursive_refs(openapi_dict)

    logging.debug(f"Writing cleaned OpenAPI JSON to file: {output_file}")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(cleaned_openapi_dict, f, indent=2)

    logging.info("Processing complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove recursive $ref from OpenAPI JSON file.")
    parser.add_argument("-f", "--file", required=True, help="Input OpenAPI JSON file")
    parser.add_argument(
        "-o",
        "--output",
        default="cleaned_openapi.json",
        help="Output file for cleaned OpenAPI JSON (default: cleaned_openapi.json)",
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug messages")

    args = parser.parse_args()

    main(args.file, args.output, args.debug)
