# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""test synchronization between Keepass databases"""

# pylint: disable=missing-function-docstring

from datetime import datetime, timedelta
from logging import getLogger
from os import remove

import pytest
from pytz import UTC

from pwsync import KeepassDatabaseClient, PasswordDataset, PwsItem, PwsSyncer
from pwsync.common import LOGGER_NAME, PwsQueryInfo

# TODO add test related to org/organization and fav/favority not working properly

# comparing 2 kp databases
KP1_PW = "pw"
KP1_FILENAME = "tests/pw1.kdbx"
KP2_PW = KP1_PW
KP2_FILENAME = "tests/pw2.kdbx"


TITLE = "title"
NAME = "name"
SECRET = "secret"
ORGANIZATION_NAME = "organization"

SYNC = False
QUERY_INFO = PwsQueryInfo(["folder", "title"], ":", SYNC)

LOGGER = getLogger(LOGGER_NAME + "-test")


@pytest.fixture(name="cli1")
def _cli1():
    try:
        remove(KP1_FILENAME)
    except FileNotFoundError:
        pass  # maybe file did not exist
    cli = KeepassDatabaseClient(KP1_FILENAME, KP1_PW)
    yield cli


@pytest.fixture(name="ds1")
def _ds1(cli1):
    yield PasswordDataset(KP1_FILENAME, QUERY_INFO, cli1)


@pytest.fixture(name="cli2")
def _cli2():
    try:
        remove(KP2_FILENAME)
    except FileNotFoundError:
        pass  # maybe file did not exist
    cli = KeepassDatabaseClient(KP2_FILENAME, KP2_PW)
    yield cli


@pytest.fixture(name="ds2")
def _ds2(cli2):
    yield PasswordDataset(KP1_FILENAME, QUERY_INFO, cli2)


@pytest.fixture(name="sync")
def _sync(ds1, ds2):
    yield PwsSyncer(ds1, ds2)


# Nothing to sync, empty databases(up-to-date)
def test_identical_db_empty(sync):
    res = sync.sync()
    assert sum(res.values()) == 0


# Nothing to sync, both 1 minimal item in databases (up-to-date)
def test_identical_db_one_item(cli1, cli2, sync):
    item1 = cli1.create(PwsItem(TITLE, NAME, SECRET))
    item2 = cli2.create(PwsItem(TITLE, NAME, SECRET))

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["no-change"] == 1
    assert item1 == sync.unchanged[0].from_item
    assert item2 == sync.unchanged[0].to_item


# Nothing to sync, both 1 maximal item in databases (up-to-date)
def test_identical_db_one_item_full(cli1, cli2, sync):
    folder = "folder"
    note = "note"
    url = "url"
    totp = "totp"
    favorite = True
    organization = "organization"
    collections = ["collection1", "collection2"]
    item1 = cli1.create(
        PwsItem(TITLE, NAME, SECRET, folder, note, url, totp, favorite, organization, collections, SYNC)
    )
    item2 = cli2.create(
        PwsItem(TITLE, NAME, SECRET, folder, note, url, totp, favorite, organization, collections, SYNC)
    )

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["no-change"] == 1
    assert item1 == sync.unchanged[0].from_item
    assert item2 == sync.unchanged[0].to_item


# Nothing to sync, both 2 minimal item in databases (up-to-date)
def test_identical_db_two_items(cli1, cli2, sync):
    title1 = "titl1e"
    title2 = "title2"
    cli1.create(PwsItem(title1, NAME, SECRET))
    cli1.create(PwsItem(title2, NAME, SECRET))
    cli2.create(PwsItem(title1, NAME, SECRET))
    cli2.create(PwsItem(title2, NAME, SECRET))

    res = sync.sync()
    assert sum(res.values()) == 2
    assert res["no-change"] == 2
    assert len(sync.unchanged) == 2


def test_one_item_diff_one_field_update(cli1, cli2, sync, mocker):
    secret1 = "secret1"
    secret2 = "secret2"
    date = datetime(2021, 9, 1, tzinfo=UTC)
    item1 = cli1.create(PwsItem(TITLE, NAME, secret1))
    item2 = cli2.create(PwsItem(TITLE, NAME, secret2))
    mocker.patch.object(PwsItem, "get_mtime", side_effect=[date, date - timedelta(minutes=1)])

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["update"] == 1
    assert len(sync.updates) == 1
    assert item1 == sync.updates[0].from_item
    assert item2 == sync.updates[0].to_item
    assert sync.updates[0].add_props == sync.updates[0].remove_props
    assert sync.updates[0].add_props == {SECRET}


def test_one_item_diff_one_field_update_conflict(cli1, cli2, sync, mocker):
    secret1 = "secret1"
    secret2 = "secret2"
    cli1.create(PwsItem(TITLE, NAME, secret1))
    cli2.create(PwsItem(TITLE, NAME, secret2))
    date = datetime(2021, 9, 1, tzinfo=UTC)
    mocker.patch.object(PwsItem, "get_mtime", side_effect=[date, date])

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["update"] == 1
    assert len(sync.conflicts) == 1


def test_one_item_diff_one_field_add(cli1, sync):
    item1 = cli1.create(PwsItem(TITLE, NAME, SECRET))

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["create"] == 1
    assert len(sync.creates) == 1
    assert item1 == sync.creates[0].from_item


def test_one_item_diff_one_field_add_folder(cli1, sync):
    folder = "folder"
    item1 = cli1.create(PwsItem(TITLE, NAME, SECRET, folder))

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["create"] == 1
    assert len(sync.creates) == 1
    assert item1 == sync.creates[0].from_item


def test_one_item_diff_one_field_add_full(cli1, sync):
    folder = "folder/subfolder"
    note = "note"
    url = "url"
    totp = "totp"
    fav = True
    organization_uuid = "organization_uuid"
    collection_uuids = ["collection_uuid1", "collection_uuid2"]
    sync_flag = ""
    item1 = cli1.create(
        PwsItem(TITLE, NAME, SECRET, folder, note, url, totp, fav, organization_uuid, collection_uuids, sync_flag)
    )

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["create"] == 1
    assert len(sync.creates) == 1
    assert item1 == sync.creates[0].from_item


# KP Item removed (SYNC should remove it also)
def test_one_item_diff_one_delete(cli2, sync):
    item2 = cli2.create(PwsItem(TITLE, NAME, SECRET))

    res = sync.sync()
    assert sum(res.values()) == 1
    assert res["delete"] == 1
    assert len(sync.deletes) == 1
    assert item2 == sync.deletes[0].to_item


# KP Item moved path (SYNC should move the path also)

# KP Item renamed username (SYNC should rename the username also)

# KP Item updated secret (SYNC should update the secret also)

# SYNC Item added (KP should add it also)

# SYNC Item removed (KP should remove it also)

# SYNC Item moved path (KP should rename the path also)

# SYNC Item renamed username (KP should rename the username also)

# SYNC Item updated secret

# KP & SYNC Item added

# KP & SYNC Item removed

# KP & SYNC Item moved path

# KP & SYNC Item renamed username

# KP & SYNC Item updated secret
