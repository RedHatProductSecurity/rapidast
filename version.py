import os

from git import Repo
from setuptools_scm import ScmVersion
from setuptools_scm import version as _version


def get_current_branch():
    """Gets the name of the current Git branch"""
    try:
        repo_path = os.getcwd()
        repo = Repo(repo_path)
        return repo.active_branch.name
    except Exception as e:  # pylint: disable=W0718
        print(f"Error getting current branch: {e}")
        return None


def get_latest_main_tag() -> str:
    """Gets the latest tag name from the "main" branch"""
    try:
        repo_path = os.getcwd()
        repo = Repo(repo_path)

        # We could filter tags just in main, however Konflux doesn't
        # provide branches information
        tags = repo.tags
        tags = sorted(tags, key=lambda t: t.commit.committed_date, reverse=True)

        if tags:
            return str(tags[0])
        return None

    except Exception as e:  # pylint: disable=W0718
        print(f"Error getting latest tag info: {e}")
        return None


def custom_local_scheme(version: ScmVersion) -> str:
    if version.branch == "main":
        return ""

    return f"+{version.node[1:8]}-{version.node_date.strftime('%Y%m%d')}"


def custom_version_scheme(version: ScmVersion) -> str:
    latest_tag_name = get_latest_main_tag()

    fallback_tag = "0.1.0"

    if latest_tag_name:
        version.tag = latest_tag_name
    else:
        return f"{fallback_tag}"

    if version.branch == "main":
        return f"{version.format_with(latest_tag_name)}"

    return version.format_next_version(_version.guess_next_simple_semver, retain=_version.SEMVER_PATCH, fmt="{guessed}")
