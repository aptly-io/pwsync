# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""Difference operation between a "to" and "from" password dataset"""

from dataclasses import dataclass
from logging import getLogger
from typing import List, Optional, Set

from diffsync.enum import DiffSyncActions
from diffsync.logging import enable_console_logging

from .common import (
    COLLECTIONS,
    FAVORITE,
    FOLDER,
    LOGGER_NAME,
    NAME,
    NOTE,
    ORGANIZATION,
    SECRET,
    SYNC,
    TITLE,
    TOTP,
    URL,
)
from .dataset import PasswordDataset
from .item import PwsItem


@dataclass
class PwsDiffElement:
    """Holds the difference for a single "to" and "from" PwsItem"""

    add_props: Optional[Set[str]] = None
    remove_props: Optional[Set[str]] = None
    from_item: Optional[PwsItem] = None
    to_item: Optional[PwsItem] = None


class PwsSyncer:
    """Difference between "to" and "from" password datasets"""

    def __init__(self, ds1: PasswordDataset, ds2: PasswordDataset):
        self._logger = getLogger(LOGGER_NAME)
        self._ds1 = ds1
        self._ds2 = ds2

        # items only in the from password DB
        self.creates: List[PwsDiffElement] = []
        # items only in the to password DB
        self.updates: List[PwsDiffElement] = []
        # from items that are more recent than those in the to-password DB
        self.deletes: List[PwsDiffElement] = []
        # to items that are more recent than those in the from-password DB
        self.conflicts: List[PwsDiffElement] = []
        # items that are the same in the to and from-password DB
        self.unchanged: List[PwsDiffElement] = []
        # incomplete items that cannot be compared
        self.skipped: List[PwsDiffElement] = []

        # 0 for WARNING logs, 1 for INFO logs, 2 for DEBUG logs
        enable_console_logging(verbosity=0)

    def sync(self):
        """calculates differences"""

        self._ds1.load()
        self._ds2.load()

        self.creates = []
        self.updates = []
        self.deletes = []
        self.conflicts = []
        self.unchanged = []
        self.skipped = []

        diff = self._ds1.diff_to(self._ds2)
        self.conflicts = []
        for diff_element in diff.get_children():
            self._logger.debug("action: %s", diff_element.action)
            # self._print(diff_element)
            if diff_element.action == DiffSyncActions.CREATE:
                self._create(diff_element)
            elif diff_element.action == DiffSyncActions.DELETE:
                self._delete(diff_element)
            # Seems not called, action seems to contain None instead?
            # elif "no-change" == diff_element.action:
            elif diff_element.action is None:
                self._unchanged(diff_element)
            elif diff_element.action == DiffSyncActions.UPDATE:
                self._update(diff_element)
            else:
                raise Exception(f"Unexpected action: {diff_element.action}")

        self._logger.info("diff.summary: %s", diff.summary())
        self._logger.debug("self.creates: %s", self.creates)
        self._logger.debug("self.updates: %s", self.updates)
        self._logger.debug("self.deletes: %s", self.deletes)
        self._logger.debug("self.conflicts: %s", self.conflicts)
        self._logger.debug("self.unchanged: %s", self.unchanged)
        return diff.summary()

    def _unchanged(self, diff_element):
        from_item = self._ds1.get(diff_element.type, diff_element.name).item
        to_item = self._ds2.get(diff_element.type, diff_element.name).item
        self.unchanged.append(PwsDiffElement(None, None, from_item, to_item))

    def _create(self, diff_element):
        to_add = set([TITLE, FOLDER, NAME, SECRET, NOTE, URL, TOTP, FAVORITE, ORGANIZATION, COLLECTIONS, SYNC])
        to_remove = set()
        from_item = self._ds1.get(diff_element.type, diff_element.name).item
        self.creates.append(PwsDiffElement(to_add, to_remove, from_item))

    def _delete(self, diff_element):
        to_add = set()
        to_remove = set([TITLE, FOLDER, NAME, SECRET, NOTE, URL, TOTP, FAVORITE, ORGANIZATION, COLLECTIONS, SYNC])
        to_item = self._ds2.get(diff_element.type, diff_element.name).item
        self.deletes.append(PwsDiffElement(to_add, to_remove, None, to_item))

    def _update(self, diff_element):
        # which fields change how
        add_props = set(diff_element.get_attrs_diffs()["-"].keys())
        remove_props = set(diff_element.get_attrs_diffs()["+"].keys())

        from_cred = self._ds1.get(diff_element.type, diff_element.name)
        to_cred = self._ds2.get(diff_element.type, diff_element.name)
        if from_cred.item.get_mtime() > to_cred.item.get_mtime():
            # TODO to be used elsewhere
            # changes = {k: getattr(from_cred, k) for k in to_update | to_add}
            # update_item = to_cred.item.update(**changes)
            self.updates.append(PwsDiffElement(add_props, remove_props, from_cred.item, to_cred.item))
        else:
            # to-item is more recent than from-item
            self.conflicts.append(PwsDiffElement(add_props, remove_props, from_cred.item, to_cred.item))

    def _print(self, diff_element):
        self._logger.debug("########## dir(diff_element): {type(diff_element)}, {dir(diff_element)}")
        self._logger.debug("%s: diff_element: %s", diff_element.action, {diff_element})
        self._logger.debug("%s: type: %s", diff_element.action, diff_element.type)
        self._logger.debug("%s: name: %s", diff_element.action, diff_element.name)
        self._logger.debug("%s: source_name: %s", diff_element.action, diff_element.source_name)
        self._logger.debug("%s: dest_name: %s", diff_element.action, diff_element.dest_name)
        self._logger.debug("%s: source_attrs: %s", diff_element.action, diff_element.source_attrs)
        self._logger.debug("%s: dest_attrs: %s", diff_element.action, diff_element.dest_attrs)
        self._logger.debug("%s: add_attrs: %s", diff_element.action, diff_element.add_attrs())
        self._logger.debug("%s: get_children: %s", diff_element.action, list(diff_element.get_children()))
        self._logger.debug("%s: dict: %s", diff_element.action, diff_element.dict())
        self._logger.debug("%s: keys: %s", diff_element.action, diff_element.keys)
        self._logger.debug("%s: child_diff: %s", diff_element.action, diff_element.child_diff)
        self._logger.debug("%s: get_attrs_diffs(): %s", diff_element.action, diff_element.get_attrs_diffs())
        self._logger.debug("%s: get_attrs_keys(): %s", diff_element.action, diff_element.get_attrs_keys())
        self._logger.debug("%s: get_attrs_keys(): %s", diff_element.action, diff_element.get_attrs_keys())
        # self.logger.debug(f"ds1: {dir(self.ds1)}")
        # self.logger.debug(f"ds1.get_all: {self.ds1.get_all('credential')}")
        self._logger.debug("------------------------------------------------------------")
