import os
import yaml
from rapidast import validate_config_schema, load_config_file
import configmodel

def test_validate_config_schema():
    directory = "config"
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        
        # Skip directories, only process files
        if os.path.isdir(file_path) or not filename.endswith(".yaml"):
            continue
        
        config = configmodel.RapidastConfigModel(yaml.safe_load(load_config_file(file_path)))
        assert validate_config_schema(config) == True
    