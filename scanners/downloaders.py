# This is a file with helper functions to download file with authentication.
import logging

import requests
import yaml


def anonymous_download(url, dest=None, proxy=None, verify=None):
    """Given a URL, load it using a GET request to dest"""

    logging.debug(f"Downloading {url}")
    if proxy:
        proxy = {
            "https": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
            "http": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
        }
    resp = requests.get(url, allow_redirects=True, proxies=proxy, verify=verify)
    if resp.status_code >= 400:
        logging.warning(f"Download {url} failed with {resp.status_code}.")
        return False

    if dest:
        with open(dest, "wb") as file:
            file.write(resp.content)
        logging.debug(f"Download saved in {dest}")
        return True
    else:
        logging.debug("Returning content")
        return resp.content


def oauth2_get_token_from_rtoken(auth, proxy=None, session=None, verify=None):
    """Given a rtoken, retrieve and return a Bearer token
    auth is in the form { url, client_id, rtoken }

    NOTE: if a session is provided, `verify` will not overwrite the session's `verify` state
    """

    if session is None:
        session = requests.Session()
        if verify is not None:
            session.verify = verify

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = {
        "client_id": auth["client_id"],
        "grant_type": "refresh_token",
        "refresh_token": auth["rtoken"],
    }
    if proxy:
        proxy = {
            "https": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
            "http": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
        }

    try:
        resp = session.post(auth["url"], data=payload, headers=headers, proxies=proxy)
        resp.raise_for_status()
    except requests.exceptions.ConnectTimeout:
        logging.error("Getting oauth2 token failed: server unresponsive. Check the Authentication URL parameters")
        return False
    except requests.exceptions.HTTPError as e:
        logging.error(f"Getting token failed: Check the RTOKEN. err details: {e}")
        return False

    try:
        token = yaml.safe_load(resp.text)["access_token"]
    except KeyError as exc:
        logging.error(f"Unable to extract access token from OAuth2 authentication:\n {str(exc)}")
        return False

    return token


def authenticated_download_with_rtoken(url, dest, auth, proxy=None, verify=None):
    """Given a URL and Oauth2 authentication parameters, download the URL and store it at `dest`"""

    session = requests.Session()
    if verify is not None:
        session.verify = verify

    # get a token
    token = oauth2_get_token_from_rtoken(auth, proxy, session)
    if not token:
        return False
    authenticated_headers = {"Authorization": f"Bearer {token}"}

    if proxy:
        proxy = {
            "https": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
            "http": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
        }

    resp = session.get(url, proxies=proxy, headers=authenticated_headers)

    if resp.status_code >= 400:
        logging.warning(f"ERROR: download failed with {resp.status_code}. Aborting download for {url}")
        return False

    with open(dest, "w", encoding="utf-8") as file:
        file.write(resp.text)

    logging.debug(f"Successful download of {url} into {dest}")
    return True
