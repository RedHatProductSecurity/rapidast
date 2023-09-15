import logging
from urllib import parse

import requests


class DefectDojo:
    """This class instanciates a connection to DefectDojo, and pushes reports"""

    DD_CONNECT_TIMEOUT = 10  # in seconds

    def __init__(self, base_url, username=None, password=None, token=None):
        if not base_url:
            raise ValueError(
                "Defect Dojo invalid configuration: URL is a mandatory value"
            )
        parsed = parse.urlparse(base_url)  # expects to raise exception on invalid URL
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Defect Dojo invalid configuration: URL is not correct")

        self.base_url = base_url
        self.username = username
        self.password = password
        self.token = token
        self.headers = {}
        if token:
            self.headers["Authorization"] = f"Token {token}"

    def _auth_and_set_token(self):
        """Force a refresh of the token using the username/password"""
        logging.debug("Defect Dojo: refreshing token")
        if not self.username or not self.password:
            raise ValueError(
                "Defect Dojo invalid configuration: A username and a password are required to get a token"
            )
        url = self.base_url + "/api/v2/api-token-auth/"
        data = {"username": self.username, "password": self.password}

        try:
            resp = requests.post(url, timeout=self.DD_CONNECT_TIMEOUT, data=data)
            resp.raise_for_status()

            logging.debug(f"resp: {resp.json()}")
            self.token = resp.json()["token"]

            self.headers["Authorization"] = f"Token {self.token}"
            logging.debug("Defect Dojo: successfully refreshed token")
        except requests.exceptions.ConnectTimeout as e:
            logging.error(
                f"Getting token failed. Check the URL for defectDojo in config file. err details: {e}"
            )
            return 1
        except requests.exceptions.HTTPError as e:
            logging.error(
                f"Getting token failed: Check the username/password for defectDojo in the config file. err details: {e}"
            )
            return 1

        return 0

    def engagement_exists(self, engagement_id=None, name=None):
        """Return True if an engagement exists, False otherwise
        Engagement is identified either by its name or its ID (positive integer)"""
        if not self.token:
            self._auth_and_set_token()
        if engagement_id:
            resp = requests.get(
                f"{self.base_url}/api/v2/engagements/?engagment={engagement_id}",
                timeout=self.DD_CONNECT_TIMEOUT,
                headers=self.headers,
            )
        elif name:
            resp = requests.get(
                f"{self.base_url}/api/v2/engagements/?name={parse.quote_plus(name)}",
                timeout=self.DD_CONNECT_TIMEOUT,
                headers=self.headers,
            )
        else:
            raise ValueError("Either an engagement name or ID must be provided")

        if resp.status_code >= 400:
            logging.warning(
                f"Error while looking for engagement ({resp.status_code}, {resp.get('message')})"
            )
        counts = resp.json()["counts"]
        if counts > 1:
            logging.warning("Error while looking for engagement: too many hits")
        return counts >= 1

    def _private_import(self, endpoint, data, filename):
        """Send a POST request to endpoint [typically import or reimport], with data and filname"""

        mandatory = {
            "scan_type",
            "active",
            "verified",
        }
        missing = mandatory - set(data.keys())
        if missing:
            raise ValueError(f"Missing required entries for reimport: {missing}")

        if not self.token:
            if self._auth_and_set_token() == 1:
                # failed to get token
                return 1

        resp = requests.post(
            endpoint,
            timeout=self.DD_CONNECT_TIMEOUT,
            headers=self.headers,
            data=data,
            files={"file": open(filename, "rb")},  # pylint: disable=consider-using-with
        )
        if resp.status_code >= 400:
            logging.debug(vars(resp))
            err = resp.json()
            logging.error(f"Error while exporting ({resp.status_code}, {err})")

            if "Invalid token" in err["detail"]:
                logging.error(
                    "Please check your token in 'config.defectDojo' of the config file"
                )

            return 1

        return 0

    def reimport_scan(self, data, filename):
        """Reimport to an existing engagement with an existing compatible scan."""

        if not data.get("test") and not (
            data.get("engagement_name")
            and data.get("product_name")
            and data.get("test_title")
        ):
            raise ValueError(
                "Reimport needs to identify an existing test (by ID or names of product+engagement+test)"
            )

        return self._private_import(
            f"{self.base_url}/api/v2/reimport-scan/", data, filename
        )

    def import_scan(self, data, filename):
        """Import to an existing engagement."""

        if not data.get("engagement") and not (
            data.get("engagement_name") and data.get("product_name")
        ):
            raise ValueError(
                "Import needs to identify an existing engagement (by ID or names of product+engagement)"
            )

        return self._private_import(
            f"{self.base_url}/api/v2/import-scan/", data, filename
        )

    def import_or_reimport_scan(self, data, filename):
        """Decide wether to import or reimport. Based on:
        - If the data contains a test ID ("test"): it's a reimport
        - Otherwise import
        """
        if not data or not filename:
            # missing data means nothing to do
            logging.debug("Insufficient data for Defect Dojo")
            return 1

        if data.get("test"):
            return self.reimport_scan(data, filename)
        else:
            return self.import_scan(data, filename)
