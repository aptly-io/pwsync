# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""common constants and helper functions"""

from dataclasses import dataclass
from typing import List

LOGGER_NAME = "PWSYNC"

TITLE = "title"
FOLDER = "folder"
NAME = "name"
SECRET = "secret"
NOTE = "note"
URL = "url"
TOTP = "totp"
FAVORITE = "favorite"
ORGANIZATION = "organization"
COLLECTIONS = "collections"
MTIME = "mtime"
SYNC = "sync"

PWS_TOTP = "pws_totp"
PWS_FAVORITE = "pws_fav"
PWS_ORGANIZATION = "pws_org"
PWS_COLLECTIONS = "pws_col"
PWS_SYNC = "pws_sync"

Key = bytes


def to_bool(value: str) -> bool:
    """interprets given value as true or false"""
    return value is not None and value.lower() in ["true", "t", "1", "yes", "y", "on", "pass", "success", "ok", "oke"]


class PwsMissingOrganization(Exception):
    """use of collections requires an organization"""


class PwsDuplicate(Exception):
    """already exists"""


class PwsNotFound(Exception):
    """does not exist"""


class PwsUnsupported(Exception):
    """unsupported action/option"""


@dataclass
class PwsQueryInfo:
    """the property values used to build a unique password database entry key"""

    ids: List[str]
    id_sep: str = ":"
    sync: bool = True


@dataclass
class RunOptions:
    """options on how to perform the syncing"""

    dry_run: bool = False
    auto_update: bool = False
    auto_create: bool = False
