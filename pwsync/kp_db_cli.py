# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""CRUD operations on a Keepass database with the PwsItem"""

from json import dumps, loads
from json.decoder import JSONDecodeError
from logging import getLogger
from os.path import exists
from pathlib import Path
from typing import List, Optional
from uuid import UUID

from pykeepass import PyKeePass, create_database
from pykeepass.entry import Entry  # type: ignore
from pykeepass.group import Group  # type: ignore

from .common import (
    LOGGER_NAME,
    PWS_COLLECTIONS,
    PWS_FAVORITE,
    PWS_ORGANIZATION,
    PWS_SYNC,
    PWS_TOTP,
    Key,
    to_bool,
)
from .database_cli import PwsDatabaseClient
from .item import PwsItem


def _to_folder(entry: Entry):
    return "/".join(entry.group.path)


class KeepassDatabaseClient(PwsDatabaseClient):
    """Implements the CRUD operation on a Keepass database with the PyKeepass module"""

    def __init__(self, filename: str, db_password=None):
        super().__init__()
        self._logger = getLogger(LOGGER_NAME)
        if not exists(filename):
            self._kp = create_database(filename, db_password)
            self.name = Path(filename).stem
        else:
            self._kp = PyKeePass(filename, db_password)

    def create(self, item: PwsItem) -> PwsItem:
        """creates a Keepass Entry based on given item"""
        # TODO checking for duplicates?

        group = self._find_group(item.folder, create=True)

        entry = self._kp.add_entry(group, item.title, item.name, item.secret, item.url, item.note)
        if item.totp:
            entry.set_custom_property(PWS_TOTP, item.totp)
        if item.favorite:
            entry.set_custom_property(PWS_FAVORITE, str(item.favorite))
        if item.organization:
            entry.set_custom_property(PWS_ORGANIZATION, item.organization)
        if item.collections:
            entry.set_custom_property(PWS_COLLECTIONS, dumps(item.collections))
        if item.sync:
            entry.set_custom_property(PWS_SYNC, str(item.sync))
        self._kp.save()

        return self._entry2item(entry)

    def read(self, key: Optional[Key] = None, sync_flag: Optional[bool] = None) -> List[PwsItem]:
        """reads a Keepass Entry/ies with given optional key and sync flag"""
        if key is None:
            entries = self._kp.entries
        else:
            entries = self._kp.find_entries_by_uuid(UUID(bytes=key))
            assert len(entries) in [0, 1], "uuid must be unique"

        if sync_flag:

            def has_bw(entry):
                return PWS_SYNC in entry.custom_properties

            return [self._entry2item(e) for e in entries if has_bw(e)]

        return [self._entry2item(e) for e in entries]

    def update(self, key: Key, item: PwsItem) -> PwsItem:
        """updates a Keepass Entry with given key,
        based on the values in given item"""

        # Note once an Entry's field value is set, PyKeepass cannot turn it into None

        # pylint: disable=too-many-branches
        entry = self._get_entry(key)
        group = self._find_group(item.folder)
        if group.uuid != entry.group.uuid:
            self._kp.move_entry(entry, group)

        if item.title != entry.title:
            entry.title = "" if item.title is None else item.title
        if item.note != entry.notes:
            entry.notes = "" if item.note is None else item.note
        if item.name != entry.username:
            entry.username = "" if item.name is None else item.name
        if item.secret != entry.password:
            entry.password = "" if item.secret is None else item.secret
        if item.url != entry.url:
            entry.url = "" if item.url is None else item.url

        props = entry.custom_properties
        if not item.favorite:
            if PWS_FAVORITE in props:
                entry.delete_custom_property(PWS_FAVORITE)
        elif item.favorite != to_bool(props.get(PWS_FAVORITE)):
            entry.set_custom_property(PWS_FAVORITE, str(item.favorite))
        if item.organization is None:
            if PWS_ORGANIZATION in props:
                entry.delete_custom_property(PWS_ORGANIZATION)
        elif item.organization != props.get(PWS_ORGANIZATION):
            entry.set_custom_property(PWS_ORGANIZATION, item.organization)
        if item.collections is None:
            if PWS_COLLECTIONS in props:
                entry.delete_custom_property(PWS_COLLECTIONS)
        elif item.collections != props.get(PWS_COLLECTIONS):
            entry.set_custom_property(PWS_COLLECTIONS, dumps(item.collections))
        if item.sync is None:
            if PWS_SYNC in props:
                entry.delete_custom_property(PWS_SYNC)
        elif item.sync != props.get(PWS_SYNC):
            entry.set_custom_property(PWS_SYNC, str(item.sync))
        if item.totp is None:
            if PWS_TOTP in props:
                entry.delete_custom_property(PWS_TOTP)
        elif item.totp != props.get(PWS_TOTP):
            entry.set_custom_property(PWS_TOTP, item.totp)
        # pylint: enable=too-many-branches

        self._kp.save()
        return self._entry2item(entry)

    def delete(self, key: Key) -> PwsItem:
        """deletes the Keepass Entry with given key"""
        entry = self._get_entry(key)
        item = self._entry2item(entry)
        self._kp.delete_entry(entry)
        self._kp.save()
        return item

    def _find_group(self, folder=None, create=True) -> Group:
        if not folder:
            return self._kp.root_group
        path = folder.strip("/").split("/")
        group = self._kp.find_groups(path=path)
        if group or not create:
            return group  # the group or None
        parent_group = self._find_group("/".join(path[:-1]))
        return self._kp.add_group(parent_group, path[-1])

    def _get_entry(self, key: Key) -> Entry:
        entries = self._kp.find_entries_by_uuid(UUID(bytes=key))
        assert len(entries) == 1, "expected just 1 entry"
        return entries[0]

    def _entry2item(self, entry: Entry) -> PwsItem:
        props = entry.custom_properties
        pws_fav = PWS_FAVORITE

        if PWS_COLLECTIONS in props:
            # TODO how to catch and report errors (add to skipped entries)
            # serialized as json
            try:
                prop_value = props.get(PWS_COLLECTIONS)
                collections = loads(prop_value)
            except JSONDecodeError as err:
                self._logger.error("Failed json.loads(%s) (%s)", prop_value, PWS_COLLECTIONS)
                self._logger.error("Failed json.loads: %s", err)
                collections = None
        else:
            collections = None

        return PwsItem(
            entry.title,
            entry.username,
            entry.password,
            _to_folder(entry),
            entry.notes,
            entry.url,
            props.get(PWS_TOTP) if PWS_TOTP in props else None,
            to_bool(props.get(pws_fav)) if pws_fav in props else False,
            props.get(PWS_ORGANIZATION) if PWS_ORGANIZATION in props else None,
            collections,
            props.get(PWS_SYNC) if PWS_SYNC in props else None,
            entry.mtime,
            entry.uuid.bytes,
        )
