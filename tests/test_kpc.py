# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""KeepassDatabaseClient tests"""

# pylint: disable=missing-function-docstring

import uuid
from os import remove

import pytest

from pwsync import KeepassDatabaseClient, PwsItem

KP1_PW = "pw"
KP1_FILENAME = "tests/pw1.kdbx"


@pytest.fixture(name="kpc")
def fixture_kpc():
    remove(KP1_FILENAME)
    # try: remove(KP1_FILENAME)
    # except: pass # maybe file did not exist
    cli = KeepassDatabaseClient(KP1_FILENAME, KP1_PW)
    yield cli
    cli = None


def test_no_items(kpc):
    assert [] == kpc.read()


def test_create_empty_folder(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    folder = ""
    item = kpc.create(PwsItem(title, name, secret, folder))
    assert item.folder is None


def test_create_root_folder(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    folder = "/"
    item = kpc.create(PwsItem(title, name, secret, folder))
    assert item.folder is None


def test_create_none_folder(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    folder = None
    item = kpc.create(PwsItem(title, name, secret, folder))
    assert item.folder is None


def test_create_only_title_name_secret(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    item = kpc.create(PwsItem(title, name, secret))
    assert title == item.title
    assert name == item.name
    assert secret == item.secret
    assert item.note is None
    assert item.url is None
    assert item.folder is None
    assert len(kpc.read()) == 1
    assert item == kpc.read()[0]
    assert item == kpc.read(item.key)[0]


def test_create_only_title_name_secret_path(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    folder = "path1/path1_1"
    i = kpc.create(PwsItem(title, name, secret, folder))
    assert title == i.title
    assert name == i.name
    assert secret == i.secret
    assert folder == i.folder
    assert i.note is None
    assert i.url is None
    assert len(kpc.read()) == 1
    assert i == kpc.read()[0]
    assert i == kpc.read(i.key)[0]


def test_create_many_params(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    folder = "path1/path1_1"
    note = "My note:\nThere are many ...\nDont count the lines\n"
    uri = "https://droom.be"
    totp = "totp"
    favorite = True
    organization = "organization"
    # TODO collections
    i = kpc.create(PwsItem(title, name, secret, folder, note, uri, totp, favorite, organization))
    assert title == i.title
    assert name == i.name
    assert secret == i.secret
    assert folder == i.folder
    assert note == i.note
    assert uri == i.url
    assert len(kpc.read()) == 1
    assert i == kpc.read()[0]
    assert i == kpc.read(i.key)[0]


def test_create_2_with_same_folder(kpc):
    title = "title"
    name1 = "name1"
    name2 = "name2"
    secret = "secret"
    folder = "priv/shop"
    item1 = kpc.create(PwsItem(title, name1, secret, folder))
    item2 = kpc.create(PwsItem(title, name2, secret, folder))
    assert name1 == item1.name
    assert name2 == item2.name
    items = kpc.read()
    assert len(items) == 2
    assert item1.folder == item2.folder


def test_create_duplicate_without_folder(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    kpc.create(PwsItem(title, name, secret))
    with pytest.raises(Exception):
        # Exception: An entry TITLE already exists in "Group: "
        kpc.create(PwsItem(title, name, secret))


def test_create_duplicate_with_folder(kpc):
    title = "title"
    folder = "priv/shop"
    name = "name"
    secret = "secret"
    kpc.create(PwsItem(title, name, secret, folder))
    with pytest.raises(Exception):
        # Exception: An entry TITLE already exists in "Group: "priv/shop"
        kpc.create(PwsItem(title, name, secret, folder))


def test_create_read_bw(kpc):
    title1 = "title1"
    title2 = "title2"
    name = "name"
    secret = "secret"
    sync = True
    kpc.create(PwsItem(title1, name, secret))
    kpc.create(PwsItem(title2, name, secret, sync=sync))
    assert len(kpc.read()) == 2
    assert len(kpc.read(sync_flag=True)) == 1


def test_read_one_only_title_name_secret(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    created_item = kpc.create(PwsItem(title, name, secret))
    read_items = kpc.read(created_item.key)
    assert len(read_items) == 1
    read_item = read_items[0]
    assert title == read_item.title
    assert name == read_item.name
    assert secret == read_item.secret
    assert read_item.folder is None
    assert read_item.note is None
    assert read_item.url is None
    assert read_item.totp is None
    assert not read_item.favorite
    assert read_item.organization is None
    assert read_item.collections is None
    assert read_item.sync is None
    assert created_item.get_mtime() == read_item.get_mtime()


def test_read_two_only_title_name_secret(kpc):
    title1 = "title1"
    title2 = "title2"
    name = "name"
    secret = "secret"
    created_item1 = kpc.create(PwsItem(title1, name, secret))
    created_item2 = kpc.create(PwsItem(title2, name, secret))
    read_items = kpc.read()
    assert len(read_items) == 2
    read_item1 = kpc.read(created_item1.key)[0]
    read_item2 = kpc.read(created_item2.key)[0]
    assert title1 == read_item1.title
    assert title2 == read_item2.title


def test_update(kpc):
    title = "title"
    folder = "priv/shop"
    note = "note"
    url = "url"
    name = "name"
    secret = "secret"
    totp = "totp"
    favorite = True
    organization = "organization"
    collections = "collection"
    sync = True
    created_item = kpc.create(
        PwsItem(title, name, secret, folder, note, url, totp, favorite, organization, collections, sync)
    )
    # pylint: disable=too-many-locals
    new_title = "new_title"
    new_folder = "priv/new_shop"
    new_note = "new_note"
    new_url = "new_url"
    new_name = "new_name"
    new_secret = "new_secret"
    new_totp = "new_totp"
    new_organization = "new_organization"
    new_collections = "new_collections"
    new_favorite = False
    new_bw = False
    updating_item = created_item.update(
        title=new_title,
        name=new_name,
        secret=new_secret,
        folder=new_folder,
        note=new_note,
        url=new_url,
        totp=new_totp,
        favorite=new_favorite,
        organization=new_organization,
        collections=new_collections,
        sync=sync,
    )
    updated_item = kpc.update(updating_item.key, updating_item)

    assert new_title == updated_item.title
    assert new_folder == updated_item.folder
    assert new_note == updated_item.note
    assert new_name == updated_item.name
    assert new_secret == updated_item.secret
    assert new_url == updated_item.url
    assert new_totp == updated_item.totp
    assert new_organization == updated_item.organization
    assert new_collections == updated_item.collections
    assert new_favorite == updated_item.favorite
    assert new_bw == updated_item.favorite
    items = kpc.read()
    assert len(items) == 1
    # pylint: enable=too-many-locals


def test_update_remove_fields(kpc):
    title = "title"
    folder = "priv/shop"
    note = "note"
    url = "url"
    name = "name"
    secret = "secret"
    totp = "totp"
    favorite = True
    organization = "organization"
    collections = "collection"
    sync = True
    created_item = kpc.create(
        PwsItem(title, name, secret, folder, note, url, totp, favorite, organization, collections, sync)
    )
    # pylint: disable=too-many-locals
    new_title = "new_title"
    updating_item = created_item.update(
        title=new_title,
        name=None,
        secret=None,
        folder=None,
        note=None,
        url=None,
        totp=None,
        favorite=False,
        organization=None,
        collections=None,
        sync=None,
    )
    updated_item = kpc.update(updating_item.key, updating_item)

    assert new_title == updated_item.title
    # once a field has been set in an Entry, it cannot be removed
    # therefore a None resets the Entry's value to ""
    # hence the "not" in the test
    assert not updated_item.folder
    assert not updated_item.name
    assert not updated_item.secret
    assert not updated_item.note
    assert not updated_item.url
    # a custom_property can be deleted however hence "is None" in the test
    assert updated_item.totp is None
    assert updated_item.organization is None
    assert updated_item.collections is None
    assert not updated_item.favorite
    assert updated_item.sync is None
    items = kpc.read()
    assert len(items) == 1
    # pylint: enable=too-many-locals


def test_update_multi(kpc):
    """edit the same item again, last edit is a do nothing"""
    # pylint: disable=too-many-locals
    title = "title"
    folder = "priv/shop"
    note = "note"
    url = "url"
    name = "name"
    secret = "secret"
    totp = "totp"
    favorite = True
    organization = "organization"
    collections = "collections"
    i = kpc.create(PwsItem(title, name, secret, folder, note, url, totp, favorite, organization, collections))

    new_title = "new_title"
    new_folder = "priv/new_shop"
    new_note = "new_note"
    new_name = "new_name"
    new1 = kpc.update(i.key, PwsItem(new_title, new_name, None, new_folder, new_note))

    assert i.key == new1.key
    assert new_folder == new1.folder
    assert new_note == new1.note
    assert new_name == new1.name

    new2_folder = "priv/new_shop_2"
    kpc.update(i.key, PwsItem(None, None, None, new2_folder))

    new3 = kpc.update(i.key, PwsItem(None, None, None, new2_folder))

    items = kpc.read()
    assert len(items) == 1
    assert new3.key == items[0].key
    assert new2_folder == new3.folder
    # pylint: enable=too-many-locals


def test_update_wrong_uuid(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    kpc.create(PwsItem(title, name, secret))

    new_name = "new_name"
    new_folder = "priv/new_shop"
    with pytest.raises(AssertionError):
        key = uuid.uuid4().bytes
        kpc.update(key, PwsItem(None, new_name, None, new_folder))


def test_delete(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    i = kpc.create(PwsItem(title, name, secret))

    deleted_item = kpc.delete(i.key)
    assert len(kpc.read()) == 0
    assert title == deleted_item.title
    assert name == deleted_item.name
    assert deleted_item.folder is None


def test_delete_wrong_uuid(kpc):
    title = "title"
    name = "name"
    secret = "secret"
    kpc.create(PwsItem(title, name, secret))

    with pytest.raises(AssertionError):
        kpc.delete(uuid.uuid4().bytes)
    assert len(kpc.read()) == 1
