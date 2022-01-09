# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""Generic immutable holder of a credential from a password database"""

# TODO support:
# - multiple fields (from bitwarden)
# - multiple url (from bitwarden)

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

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
    Key,
    PwsMissingOrganization,
    PwsQueryInfo,
)


class PwsItem:
    """Generic (minimal) immutable password-item passed in
    CRUD operations on different password databases"""

    # pylint: disable=too-many-arguments, unused-argument
    def __init__(
        self,
        title: str,
        name: str,
        secret: str,
        folder: Optional[str] = None,  # TODO replace default None with empty string ""?
        note: Optional[str] = None,
        url: Optional[str] = None,
        totp: Optional[str] = None,
        favorite: bool = False,
        organization: Optional[str] = None,
        collections: Optional[List[str]] = None,
        sync: Optional[Any] = None,
        mtime: Optional[datetime] = None,
        key: Optional[Key] = None,
    ):
        if folder == "":
            folder = None
        # all arguments as a dict and still benefit parameter type checking
        self._fields = locals()
        del self._fields["self"]
        if collections == []:
            self._fields[COLLECTIONS] = None  # convert [] (empty list) to None
        if collections and not organization:
            raise PwsMissingOrganization("collections require an organization")
        self._mtime = self._fields.pop("mtime")
        self._key = self._fields.pop("key")

    # pylint: enable=too-many-arguments, unused-argument
    def update(self, **kwargs) -> PwsItem:
        """returns a copy of self with the updates given in kwargs"""
        updated = self.__new__(self.__class__)
        updated._fields = self._fields.copy()
        updated._fields.update(kwargs)  # TODO types validation?
        # the use of setattr() avoids pylint's W0212
        # W0212: getter to a protected member _mtime of a client class
        # (protected-access)
        # updated._mtime = self.mtime
        setattr(updated, "_mtime", self.get_mtime)
        setattr(updated, "_key", self.key)
        return updated

    def make_id(self, key_info: PwsQueryInfo) -> str:
        """returns this item's identifying string by concatenating the values of given properties,
        separated by given separator"""
        return key_info.id_sep.join(["" if v is None else v for v in [getattr(self, id) for id in key_info.ids]])

    @property
    def title(self) -> str:
        """title getter"""
        return self._fields[TITLE]

    @property
    def name(self) -> str:
        """username getter"""
        return self._fields[NAME]

    @property
    def secret(self) -> str:
        """password/secret getter"""
        return self._fields[SECRET]

    @property
    def folder(self) -> Optional[str]:
        """folder/path/directry/group getter"""
        return self._fields[FOLDER]

    @property
    def note(self) -> Optional[str]:
        """note getter"""
        return self._fields[NOTE]

    @property
    def url(self) -> Optional[str]:
        """website URL getter"""
        return self._fields[URL]

    @property
    def totp(self) -> Optional[str]:
        """One-Time-Password getter"""
        return self._fields[TOTP]

    @property
    def favorite(self) -> bool:
        """is-favorite getter"""
        return self._fields[FAVORITE]

    @property
    def organization(self) -> Optional[str]:
        """organization getter"""
        return self._fields[ORGANIZATION]

    @property
    def collections(self) -> Optional[list[str]]:
        """collections getter"""
        return self._fields[COLLECTIONS]

    @property
    def sync(self) -> Optional[Any]:
        """bitwarden flag getter"""
        return self._fields[SYNC]

    def get_mtime(self) -> Optional[datetime]:
        """modification timestamp getter, a function so it can be mocked"""
        return self._mtime

    @property
    def key(self) -> Optional[bytes]:
        """key getter"""
        return self._key

    def __eq__(self, other):
        # mtime and key are ignore on purpose
        if isinstance(other, PwsItem):
            return self._fields == other._fields
        return NotImplemented

    def __hash__(self):
        # necessary for instances in dicts and sets.
        # _mtime and _key are ignore on purpose
        return hash(self._fields.values())

    def __str__(self):
        key = self._key.hex() if self._key else ""
        mtime = self._mtime if self._mtime else ""
        folder = "" if not self.folder else self.folder
        title = self._fields[TITLE]
        return f"{folder}:{title}:{self._fields[NAME]} {key} {mtime}".strip()
