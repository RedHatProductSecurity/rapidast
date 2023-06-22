import logging
import unittest

from utils import add_logging_level


class TestAddLoggingLevel(unittest.TestCase):
    def test_add_logging_level(self):
        add_logging_level("VERBOSE", logging.DEBUG + 5)
        logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.VERBOSE)
        with self.assertLogs(level="VERBOSE") as cm:
            logging.verbose("verbose")
            logging.debug("debug")
        self.assertEqual(cm.output, ["VERBOSE:root:verbose"])
