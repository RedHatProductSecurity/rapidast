import os

import yaml

import configmodel
from rapidast import load_config_file
from rapidast import validate_config_schema


def test_validate_config_schema():
    directory = "config"

    for v in ["RTOKEN", "EXPORTED_TOKEN"]:
        os.environ[v] = "dummy value"

    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)

        if os.path.isdir(file_path) or not filename.endswith(".yaml"):
            continue

        assert validate_config_schema(file_path) == True
