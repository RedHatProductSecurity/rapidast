import pytest
import requests

from exports.defect_dojo import DefectDojo


# DefectDojo integration tests
def test_dd_invalid_url_scheme():
    with pytest.raises(ValueError):
        defect_d = DefectDojo("invalid_url")


def test_dd_auth_and_set_token_no_username():
    defect_d = DefectDojo("https://127.0.0.1:12345")
    with pytest.raises(ValueError) as e_info:
        defect_d._auth_and_set_token()

    assert "A username and a password are required" in str(e_info)


def test_dd_auth_and_set_token_non_existent_url():
    # assuming 127.0.0.1:12345 is non-existent
    defect_d = DefectDojo(
        "https://127.0.0.1:12345", "random_username", "random_password", "random_token"
    )
    with pytest.raises(requests.exceptions.ConnectionError):
        defect_d._auth_and_set_token()
