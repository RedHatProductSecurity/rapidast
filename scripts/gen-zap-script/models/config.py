from models.model_base import ModelBase
from parsers.yaml_parser import YAMLParser


class Config(ModelBase, YAMLParser):
    def __init__(self, config_file):
        self.parse_content(config_file)

    @property
    def proxies(self):
        return self.q.general.localProxy
