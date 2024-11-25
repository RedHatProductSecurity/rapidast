import pytest

from scanners.nessus.tools.convert_nessus_csv_to_sarif import convert_csv_to_sarif
from scanners.nessus.tools.convert_nessus_csv_to_sarif import is_file
from scanners.nessus.tools.convert_nessus_csv_to_sarif import map_level
from scanners.nessus.tools.convert_nessus_csv_to_sarif import nessus_info
from scanners.nessus.tools.convert_nessus_csv_to_sarif import uri

TEST_DATA_DIR = "tests/scanners/nessus/tools/test_data_convert_nessus_csv_to_sarif/"


def test_map_level():
    """
    Tests map level function returns appropriate SARIF equivalent
    """
    assert map_level("Critical") == "error"
    assert map_level("High") == "error"
    assert map_level("Medium") == "warning"
    assert map_level("Low") == "note"
    assert map_level("None") == "none"
    assert map_level("foo") == "none"


def test_nessus_info():
    """
    Tests nessus_info function to extract information from plugin 19506
    """
    # Abbreviated output
    plugin_output = (
        "Information about this scan : \n"
        "\n"
        "Nessus version : 10.8.3\n"
        "Nessus build : 20010\n"
        "Plugin feed version : 202410091249\n"
        "Scanner edition used : Nessus\n"
        "Scanner OS : LINUX\n"
    )

    assert nessus_info("Nessus version", plugin_output) == "10.8.3"
    assert nessus_info("Scanner edition used", plugin_output) == "Nessus"
    assert nessus_info("Does not exist", plugin_output) == "DNE"


def test_is_file():
    """
    Test is_file function used to determine if file or stdin should be used
    """
    assert is_file(None) is False
    assert is_file("-") is False
    assert is_file("filename") is True


def test_uri():
    """
    Tests uri function to format string to be used in artifactLocation.uri field
    """
    assert uri("localhost", "443") == "localhost:443"
    assert uri("localhost", "0") == "localhost"


def test_convert_csv_to_sarif_file():
    """
    Testing conversion using file
    """
    csv_file = TEST_DATA_DIR + "nessus_TEST.csv"
    sarif_result = convert_csv_to_sarif(csv_file)

    assert sarif_result["runs"][0]["tool"]["driver"]["name"] == "Nessus"
    assert sarif_result["runs"][0]["tool"]["driver"]["fullName"] == "Nessus 10.8.3 py-test Policy"
    assert sarif_result["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "10180"
    assert sarif_result["runs"][0]["tool"]["driver"]["rules"][1]["id"] == "19506"
    assert len(sarif_result["runs"][0]["results"]) == 2
    assert sarif_result["version"] == "2.1.0"
    assert (
        sarif_result["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "127.0.0.1"
    )
