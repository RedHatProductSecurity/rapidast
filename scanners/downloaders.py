# This is a file with helper functions to download file with authentication.
import logging

import requests
import yaml


def anonymous_download(url, dest=None, proxy=None):
    """Given a URL, load it using a GET request to dest"""

    logging.debug(f"Downloading {url}")
    if proxy:
        proxy = {
            "https": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
            "http": f"http://{proxy['proxyHost']}:{proxy['proxyPort']}",
        }
    resp = requests.get(url, allow_redirects=True, proxies=proxy)
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


def authenticated_download_with_rtoken(url, dest, auth, proxy=None):
    """Given a URL and Oauth2 authentication parameters, download the URL and store it at `dest`"""

    session = requests.Session()

    # get a token
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

    resp = session.post(auth["url"], data=payload, headers=headers, proxies=proxy)

    if resp.status_code != 200:
        logging.warning(
            f"Unable to get a bearer token. Aborting manual download for {url}"
        )
        return False

    try:
        token = yaml.safe_load(resp.text)["access_token"]
    except Exception as exc:
        raise RuntimeError(
            f"Unable to extract access token from OAuth2 authentication:\n {str(exc)}"
        ) from exc
    authenticated_headers = {"Authorization": f"Bearer {token}"}

    resp = session.get(url, proxies=proxy, headers=authenticated_headers)

    if resp.status_code >= 400:
        logging.warning(
            f"ERROR: download failed with {resp.status_code}. Aborting download for {url}"
        )
        return False

    with open(dest, "w", encoding="utf-8") as file:
        file.write(resp.text)

    logging.debug(f"Successful download of {url} into {dest}")
    return True
