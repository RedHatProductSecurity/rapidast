import json
import logging
from urllib import parse
from urllib import request

import requests


class DefectDojo:
    """This class instanciates a connection to DefectDojo, and pushes reports"""

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

    def get_token(self):
        """Force a refresh of the token using the username/password"""
        logging.debug("Defect Dojo: refreshing token")
        if not self.username or not self.password:
            raise ValueError(
                "Defect Dojo invalid configuration: A username and a password are required to get a token"
            )
        url = self.base_url + "/api/v2/api-token-auth/"
        data = {"username": self.username, "password": self.password}
        data = parse.urlencode(data).encode("ascii")

        with request.urlopen(url, data=data) as resp:
            if resp.getcode() >= 400:
                logging.warning(
                    f"Defect Dojo did not answer as expected during login (status: {resp.getcode()})"
                )

            self.token = json.load(resp)["token"]

        self.headers["Authorization"] = f"Token {self.token}"
        logging.debug("Defect Dojo: successfully refreshed token")

    def engagement_exists(self, engagement_id=None, name=None):
        """Return True if an engagement exists, False otherwise
        Engagement is identified either by its name or its ID (positive integer)"""
        if not self.token:
            self.get_token()
        if engagement_id:
            resp = requests.get(
                f"{self.base_url}/api/v2/engagements/?engagment={engagement_id}",
                headers=self.headers,
            )
        elif name:
            resp = requests.get(
                f"{self.base_url}/api/v2/engagements/?name={parse.quote_plus(name)}",
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
            self.get_token()

        resp = requests.post(
            endpoint,
            headers=self.headers,
            data=data,
            files={"file": open(filename, "rb")},  # pylint: disable=consider-using-with
        )
        if resp.status_code >= 400:
            print(vars(resp))
            err = resp.json()
            logging.warning(f"Error while exporting ({resp.status_code}, {err})")

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

        self._private_import(f"{self.base_url}/api/v2/reimport-scan/", data, filename)

    def import_scan(self, data, filename):
        """Import to an existing engagement."""

        if not data.get("engagement") and not (
            data.get("engagement_name") and data.get("product_name")
        ):
            raise ValueError(
                "Import needs to identify an existing engagement (by ID or names of product+engagement)"
            )

        self._private_import(f"{self.base_url}/api/v2/import-scan/", data, filename)

    def import_or_reimport_scan(self, data, filename):
        """Decide wether to import or reimport. Based on:
        - If the data contains a test ID ("test"): it's a reimport
        - Otherwise import
        """
        if not data or not filename:
            # missing data means nothing to do
            logging.debug("Insufficient data for Defect Dojo")
            return

        if data.get("test"):
            self.reimport_scan(data, filename)
        else:
            self.import_scan(data, filename)
