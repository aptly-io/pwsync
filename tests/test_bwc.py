# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""BitwardenClientWrapper tests"""

# pylint: disable=missing-function-docstring

from datetime import datetime, timezone
from logging import getLogger
from os import environ

import pytest

from pwsync import BitwardenClientWrapper, PwsDuplicate, PwsItem, PwsUnsupported

TITLE = "title"
NAME = "name"
SECRET = "secret"
ORGANIZATION_NAME = "organization"

LOGGER_NAME = "pwsync"


@pytest.fixture(name="logger", scope="session")
def _logger():
    # see pytest logging settings in pytest.ini
    return getLogger(LOGGER_NAME)


@pytest.fixture(name="bwc", scope="session")
def _bwc():
    client_id = environ["TEST_BW_CLIENT_ID"]
    client_secret = environ["TEST_BW_CLIENT_SECRET"]
    password = environ["TEST_BW_MASTER_PASSWORD"]
    cli = BitwardenClientWrapper(client_id, client_secret, password, ["folder", "name"])
    yield cli
    cli.logout()


@pytest.fixture(autouse=True)
def clean_bw_vault(bwc, logger):
    logger.debug("Purge vault")
    # is there an alternative to purge the vault?
    for obj in bwc._list_objects():
        bwc._delete_object(obj["id"])
    for folder in bwc._list_objects("folders"):
        if folder["id"]:
            bwc._delete_object(folder["id"], "folder")
    for obj in bwc._list_objects():
        bwc._delete_object(obj["id"])
    organization_uuid = bwc._list_objects("organizations")[0]["id"]
    for collection in bwc._list_objects("org-collections", None, organization_uuid):
        bwc._delete_object(collection["id"], "org-collection", organization_uuid)
    # TODO how to delete "organizations"?


def test_no_items(bwc):
    assert [] == bwc.read()


def test_create_empty_folder(bwc):
    folder = ""
    date = datetime.now(timezone.utc)
    item = bwc.create(PwsItem(TITLE, NAME, SECRET, folder))
    assert TITLE == item.title
    assert NAME == item.name
    assert SECRET == item.secret
    assert item.folder is None
    assert date < item.get_mtime()
    assert date < item.get_mtime()


def test_create_root_folder(bwc):
    folder = "/"
    item = bwc.create(PwsItem(TITLE, NAME, SECRET, folder))
    assert item.folder is None


def test_create_none_folder(bwc):
    folder = None
    item = bwc.create(PwsItem(TITLE, NAME, SECRET, folder))
    assert item.folder is None


def test_read_one_only_title_name_secret(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))
    read_items = bwc.read(created_item.key)
    assert len(read_items) == 1
    read_item = read_items[0]
    assert TITLE == read_item.title
    assert NAME == read_item.name
    assert SECRET == read_item.secret
    assert read_item.folder is None
    assert read_item.note is None
    assert read_item.url is None
    assert read_item.totp is None
    assert not read_item.favorite
    assert read_item.organization is None
    assert read_item.collections is None
    assert read_item.sync is None

    # TODO mtime differences: where do these come from?
    # assert created_item.get_mtime() == read_item.get_mtime()


def test_create_only_title_name_secret_path(bwc):
    folder = "path1/path1_1"
    i = bwc.create(PwsItem(TITLE, NAME, SECRET, folder))
    assert TITLE == i.title
    assert NAME == i.name
    assert SECRET == i.secret
    assert folder == i.folder
    assert i.note is None
    assert i.url is None
    assert len(bwc.read()) == 1
    assert i == bwc.read()[0]
    assert i == bwc.read(i.key)[0]


def test_create_many_params(bwc):
    folder = "path1/path1_1"
    note = "My note:\nThere are many ...\nDont count the lines\n"
    uri = "https://droom.be"
    totp = "totp"
    favorite = True

    # TODO collections
    i = bwc.create(PwsItem(TITLE, NAME, SECRET, folder, note, uri, totp, favorite, ORGANIZATION_NAME))
    assert TITLE == i.title
    assert NAME == i.name
    assert SECRET == i.secret
    assert folder == i.folder
    assert note == i.note
    assert uri == i.url
    assert totp == i.totp
    assert favorite == i.favorite
    assert ORGANIZATION_NAME == i.organization
    assert len(bwc.read()) == 1
    assert i == bwc.read()[0]
    assert i == bwc.read(i.key)[0]


def test_create_empty_collections(bwc):
    collections = []
    i = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, None, False, None, collections))
    assert i.collections is None


def test_create_one_collection(bwc):
    collections = ["test"]
    i = bwc.create(
        PwsItem(
            TITLE,
            NAME,
            SECRET,
            None,
            None,
            None,
            None,
            False,
            ORGANIZATION_NAME,
            collections,
        )
    )
    assert collections == i.collections


def test_create_two_collections(bwc):
    collections = ["collection_1", "collection_2"]
    i = bwc.create(
        PwsItem(
            TITLE,
            NAME,
            SECRET,
            None,
            None,
            None,
            None,
            False,
            ORGANIZATION_NAME,
            collections,
        )
    )
    assert set(collections) == set(i.collections)


def test_create_2_with_same_folder(bwc):
    name1 = "name1"
    name2 = "name2"
    folder = "priv/shop"
    item1 = bwc.create(PwsItem(TITLE, name1, SECRET, folder))
    item2 = bwc.create(PwsItem(TITLE, name2, SECRET, folder))
    assert name1 == item1.name
    assert name2 == item2.name
    items = bwc.read()
    assert len(items) == 2
    assert item1.folder == item2.folder


def test_create_duplicate_no_folder(bwc):
    bwc.create(PwsItem(TITLE, NAME, SECRET))
    with pytest.raises(PwsDuplicate):
        bwc.create(PwsItem(TITLE, NAME, SECRET))


def test_create_duplicate_with_folder(bwc):
    # these are the same folders
    folder1 = "/priv/shop"
    folder2 = "priv/shop"
    bwc.create(PwsItem(TITLE, NAME, SECRET, folder1))
    with pytest.raises(PwsDuplicate):
        bwc.create(PwsItem(TITLE, NAME, SECRET, folder2))


def test_create_two_differ_by_name_no_folder(bwc):
    name1 = "name1"
    name2 = "name2"
    item1 = bwc.create(PwsItem(TITLE, name1, SECRET))
    item2 = bwc.create(PwsItem(TITLE, name2, SECRET))
    assert item1.name == name1
    assert item2.name == name2
    assert item1.title == item2.title
    assert item1.folder == item2.folder
    items = bwc.read()
    assert len(items) == 2


def test_create_two_differ_by_name_with_folder(bwc):
    name1 = "name1"
    name2 = "name2"
    folder = "priv/cloud/google/console"
    item1 = bwc.create(PwsItem(TITLE, name1, SECRET, folder))
    item2 = bwc.create(PwsItem(TITLE, name2, SECRET, folder))
    assert item1.name == name1
    assert item2.name == name2
    assert item1.title == item2.title
    assert item1.folder == item2.folder
    items = bwc.read()
    assert len(items) == 2


def test_create_two_differ_by_folder(bwc):
    folder1 = "priv/cloud/google/console"
    folder2 = None
    item1 = bwc.create(PwsItem(TITLE, NAME, SECRET, folder1))
    item2 = bwc.create(PwsItem(TITLE, NAME, SECRET, folder2))
    assert item1.name == NAME
    assert item2.name == NAME
    assert item1.title == TITLE
    assert item2.title == TITLE
    assert item1.folder == folder1
    assert item2.folder is None
    items = bwc.read()
    assert len(items) == 2


def test_create_two_differ_by_folder2(bwc):
    folder1 = "priv/cloud/google/console"
    folder2 = "priv/cloud/azure/console"
    item1 = bwc.create(PwsItem(TITLE, NAME, SECRET, folder1))
    item2 = bwc.create(PwsItem(TITLE, NAME, SECRET, folder2))
    assert item1.name == NAME
    assert item2.name == NAME
    assert item1.title == TITLE
    assert item2.title == TITLE
    assert item1.folder == folder1
    assert item2.folder == folder2
    items = bwc.read()
    assert len(items) == 2


def test_create_read_bw(bwc):
    name1 = "name1"
    name2 = "name2"
    sync = True
    bwc.create(PwsItem(TITLE, name1, SECRET))
    bwc.create(PwsItem(TITLE, name2, SECRET, sync=sync))
    assert len(bwc.read()) == 2
    assert len(bwc.read(sync_flag=True)) == 1


def test_read_two_only_title_name_secret(bwc):
    name1 = "name1"
    name2 = "name2"
    created_item1 = bwc.create(PwsItem(TITLE, name1, SECRET))
    created_item2 = bwc.create(PwsItem(TITLE, name2, SECRET))
    read_items = bwc.read()
    assert len(read_items) == 2
    read_item1 = bwc.read(created_item1.key)[0]
    read_item2 = bwc.read(created_item2.key)[0]
    assert name1 == read_item1.name
    assert name2 == read_item2.name


def test_update_name(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    new_name = "new_name"
    updating_item = created_item.update(name=new_name)
    updated_item = bwc.update(created_item.key, updating_item)

    assert new_name == updated_item.name
    items = bwc.read()
    assert len(items) == 1


def test_update_remove_then_add_name(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    updating_item = created_item.update(name=None)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.name is None

    updating_item = created_item.update(name=NAME)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.name == NAME


def test_update_secret(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    new_secret = "new_secret"
    updating_item = created_item.update(secret=new_secret)
    updated_item = bwc.update(created_item.key, updating_item)

    assert updated_item.secret == new_secret
    items = bwc.read()
    assert len(items) == 1


def test_update_remove_then_add_secret(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    updating_item = created_item.update(secret=None)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.secret is None

    updating_item = created_item.update(secret=SECRET)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.secret == SECRET


def test_update_folder(bwc):
    folder1 = "priv/cloud/google/console"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, folder1))

    new_folder = "priv/cloud/azure/console"
    updating_item = created_item.update(folder=new_folder)
    updated_item = bwc.update(created_item.key, updating_item)
    read_item = bwc.read(created_item.key)[0]

    assert new_folder == updated_item.folder
    assert new_folder == read_item.folder
    items = bwc.read()
    assert len(items) == 1


def test_update_note(bwc):
    note = "note"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, note))

    new_note = "new_note"
    updating_item = created_item.update(note=new_note)
    updated_item = bwc.update(created_item.key, updating_item)

    assert updated_item.note == new_note
    items = bwc.read()
    assert len(items) == 1


def test_update_remove_then_add_note(bwc):
    note = "note"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, note))

    updating_item = created_item.update(note=None)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.note is None

    updating_item = created_item.update(note=note)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.note == note


def test_update_totp(bwc):
    totp = "totp"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, totp))

    new_totp = "new_totp"
    updating_item = created_item.update(totp=new_totp)
    updated_item = bwc.update(created_item.key, updating_item)

    assert updated_item.totp == new_totp
    items = bwc.read()
    assert len(items) == 1


def test_update_remove_then_add_totp(bwc):
    totp = "totp"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, totp))

    updating_item = created_item.update(totp=None)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.totp is None

    updating_item = created_item.update(totp=totp)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.totp == totp


def test_update_url(bwc):
    url = "url"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, url))

    new_url = "new_url"
    updating_item = created_item.update(url=new_url)
    updated_item = bwc.update(created_item.key, updating_item)

    assert updated_item.url == new_url
    items = bwc.read()
    assert len(items) == 1


def test_update_remove_then_add_url(bwc):
    url = "url"
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, url))

    updating_item = created_item.update(url=None)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.url is None

    updating_item = created_item.update(url=url)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.url == url


def test_update_favorite(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    updating_item = created_item.update(favorite=True)
    updated_item = bwc.update(created_item.key, updating_item)
    assert updated_item.favorite


def test_update_sync(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, None, False, None, None, True))

    updating_item = created_item.update(sync=False)
    updated_item = bwc.update(created_item.key, updating_item)
    assert not updated_item.sync


def test_update_remove_organization(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, None, False, ORGANIZATION_NAME))

    updating_item = created_item.update(organization=None)
    # TODO how to remove the organization from an item
    with pytest.raises(PwsUnsupported):
        updated_item = bwc.update(created_item.key, updating_item)

        assert updated_item.organization is None


def test_update_add_organization(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    updating_item = created_item.update(organization=ORGANIZATION_NAME)
    # TODO how to remove the organization from an item
    with pytest.raises(PwsUnsupported):
        updated_item = bwc.update(created_item.key, updating_item)

        assert updated_item.organization is None


def test_update_collection(bwc):
    collections = ["collection_1"]
    created_item = bwc.create(
        PwsItem(
            TITLE,
            NAME,
            SECRET,
            None,
            None,
            None,
            None,
            False,
            ORGANIZATION_NAME,
            collections,
        )
    )

    new_collections = ["collection_a"]
    updating_item = created_item.update(collections=new_collections)
    # TODO how to change the collection with bw cli tool
    with pytest.raises(PwsUnsupported):
        updated_item = bwc.update(created_item.key, updating_item)
        read_item = bwc.read(created_item.key)[0]

        # TODO cannot use the return value from bw edit for collections?
        assert updated_item.collections == new_collections
        assert read_item.collections == new_collections


def test_update_add_collection(bwc):
    created_item = bwc.create(PwsItem(TITLE, NAME, SECRET, None, None, None, None, False, ORGANIZATION_NAME))

    new_collections = ["collection_1"]
    updating_item = created_item.update(collections=new_collections)
    # TODO how to change the collection with bw cli tool
    with pytest.raises(PwsUnsupported):
        updated_item = bwc.update(created_item.key, updating_item)
        read_item = bwc.read(created_item.key)[0]

        # TODO cannot use the return value from bw edit for collections?
        assert updated_item.collections == new_collections
        assert read_item.collections == new_collections


def test_update_remove_collection(bwc):
    collections = ["collection_1"]
    created_item = bwc.create(
        PwsItem(
            TITLE,
            NAME,
            SECRET,
            None,
            None,
            None,
            None,
            False,
            ORGANIZATION_NAME,
            collections,
        )
    )

    updating_item = created_item.update(collections=None)
    # TODO how to change the collection with bw cli tool
    with pytest.raises(PwsUnsupported):
        updated_item = bwc.update(created_item.key, updating_item)
        read_item = bwc.read(created_item.key)[0]

        # TODO cannot use the return value from bw edit for collections?
        assert not updated_item.collections
        assert not read_item.collections


def test_delete(bwc):
    item = bwc.create(PwsItem(TITLE, NAME, SECRET))

    deleted_item = bwc.delete(item.key)
    assert len(bwc.read()) == 0
    assert TITLE == deleted_item.title
    assert NAME == deleted_item.name
    assert deleted_item.folder is None
