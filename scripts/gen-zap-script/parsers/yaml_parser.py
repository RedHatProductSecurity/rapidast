import yaml
from parsers import ParseException
from parsers.parser_base import Parser


class YAMLParser(Parser):
    data = None

    def parse_content(self, file_object):
        """Parses yaml file"""
        try:
            self.data = yaml.safe_load(file_object)
            if self.data is None:
                raise ParseException(f"There is no data in the '{file_object.name}' file")
            if not isinstance(self.data, (dict, list)):
                raise ParseException(f"YAML from '{file_object.name}' file didn't produce a dictionary or list.")
        except yaml.YAMLError as error:
            raise ParseException(f"Something went wrong parsing the {file_object.name} file") from error
