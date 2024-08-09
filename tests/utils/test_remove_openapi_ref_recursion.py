import json

import pytest

from utils.remove_openapi_ref_recursion import remove_recursive_refs


def test_remove_recursive_refs():
    # Sample OpenAPI JSON with recursive $ref
    sample_openapi_json = {
        "components": {
            "schemas": {
                "NestedObject": {
                    "additionalProperties": {
                        "oneOf": [
                            {"$ref": "#/components/schemas/NestedObject"},
                            {"not": {"type": "object"}},
                        ]
                    },
                    "description": "An arbitrary object that does not allow empty string keys.",
                    "type": "object",
                    "x-propertyNames": {"minLength": 1},
                }
            }
        }
    }

    # Expected result after removing recursive $ref
    expected_output_json = {
        "components": {
            "schemas": {
                "NestedObject": {
                    "additionalProperties": {
                        "oneOf": [
                            # The recursive $ref should be removed here
                            {},
                            {"not": {"type": "object"}},
                        ]
                    },
                    "description": "An arbitrary object that does not allow empty string keys.",
                    "type": "object",
                    "x-propertyNames": {"minLength": 1},
                }
            }
        }
    }
    cleaned_openapi_dict = remove_recursive_refs(sample_openapi_json)
    assert cleaned_openapi_dict == expected_output_json


def test_no_change_needed():
    # Test with JSON that doesn't have recursive $ref
    non_recursive_json = {
        "components": {
            "schemas": {
                "UnleashToggleOut": {
                    "properties": {
                        "flag_value": {
                            "description": "The value of the feature flag toggle",
                            "type": "boolean",
                        },
                        "using_fallback_value": {
                            "description": "Whether the fallback value was used",
                            "type": "boolean",
                        },
                    },
                    "title": "Unleash Toggle Out",
                }
            }
        }
    }

    cleaned_openapi_dict = remove_recursive_refs(non_recursive_json)
    # The output should be the same as the input since there's no recursion
    assert cleaned_openapi_dict == non_recursive_json


def test_missing_components():
    # Test with JSON missing the 'components' key
    missing_components_json = {"info": {"title": "Test API", "version": "1.0.0"}}

    cleaned_openapi_dict = remove_recursive_refs(missing_components_json)
    # The output should be the same as the input since there's no 'components' to process
    assert cleaned_openapi_dict == missing_components_json


def test_multiple_schemas():
    # Test with multiple schemas in the components section
    multiple_schemas_json = {
        "components": {
            "schemas": {
                "Schema1": {"$ref": "#/components/schemas/Schema1"},
                "Schema2": {
                    "type": "object",
                    "properties": {"prop1": {"type": "string"}},
                },
            }
        }
    }

    expected_output = {
        "components": {
            "schemas": {
                "Schema1": {},
                "Schema2": {
                    "type": "object",
                    "properties": {"prop1": {"type": "string"}},
                },
            }
        }
    }

    cleaned_openapi_dict = remove_recursive_refs(multiple_schemas_json)
    assert cleaned_openapi_dict == expected_output
