# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""description of the model for DiffSync"""
# https://blog.networktocode.com/post/intro-to-diffing-and-syncing-data-with-diffsync/

from typing import Any, List, Optional

from diffsync import DiffSyncModel  # , DiffSyncModel, Diff, DiffSyncFlags

from .common import (
    COLLECTIONS,
    FAVORITE,
    FOLDER,
    NAME,
    NOTE,
    ORGANIZATION,
    SECRET,
    SYNC,
    TITLE,
    TOTP,
    URL,
)
from .item import PwsItem


class Credential(DiffSyncModel):
    """Description of the an element of a dataset"""

    _modelname = "credential"

    # identifies the same element among different datasets
    _identifiers = ("id",)

    # check modifications on these element's properties:
    _attributes = (TITLE, FOLDER, NAME, SECRET, NOTE, URL, TOTP, FAVORITE, ORGANIZATION, COLLECTIONS, SYNC)
    id: str
    title: str
    folder: Optional[str]
    name: Optional[str]
    secret: Optional[str]
    note: Optional[str]
    url: Optional[str]
    totp: Optional[str]
    favorite: Optional[bool]
    organization: Optional[str]
    collections: Optional[List[str]]
    sync: Optional[Any]

    # additional properties (not used by the DiffSync algo)
    item: PwsItem  # generic, immutable credential of the password database
