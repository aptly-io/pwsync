# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""PwsItem tests"""

import pytest

from pwsync import PwsItem, PwsMissingOrganization
from pwsync.common import PwsQueryInfo


def test_no_organization():
    """a collection requires an organization"""

    with pytest.raises(PwsMissingOrganization):
        PwsItem(
            "title",
            "name",
            "secret",
            None,
            None,
            None,
            None,
            None,
            None,
            ["collection_1"],
        )


def test_update1():
    """tests update()"""

    old = PwsItem("title", "name", "secret")
    new = old.update()
    assert old == new


def test_update2():
    """tests update()"""

    old = PwsItem("title", "name", "secret")
    new = old.update(title="new_title")
    assert old != new


def test_eq1():
    """tests __eq__()"""

    i = PwsItem("title", "name", "secret")
    assert Exception("") != i
    assert i != Exception("")
    assert i != 42
    assert 42 != i  # test the constant on the left on purpose


def test_eq2():
    """tests __eq__()"""

    item1 = PwsItem("title", "name", "secret")
    item2 = PwsItem("title", "name", "secret")
    assert item1 == item2
    assert len({item1, item2}) == 1
    assert str(item1) == ":title:name"


def test_eq3():
    """tests __eq__()"""

    item1 = PwsItem("title", "name", "secret", "folder")
    item2 = PwsItem("title", "name", "secret")
    assert item1 != item2
    assert len({item1, item2}) == 2
    assert str(item1) == "folder:title:name"


def test_eq4():
    """tests __eq__()"""

    item1 = PwsItem("title", "name", "secret")
    item2 = PwsItem("title", "name", "secret2")
    assert item1 != item2
    assert len({item1, item2}) == 2


def test_get_field():
    """tests getattr works"""

    item = PwsItem("title", "name", "secret")
    assert getattr(item, "title") == "title"
    assert getattr(item, "name") == "name"
    assert getattr(item, "secret") == "secret"
    assert getattr(item, "note") is None
    assert getattr(item, "folder") is None
    with pytest.raises(AttributeError):
        getattr(item, "blablabla")


def test_make_id():
    """tests make_id"""

    item = PwsItem("title", "name", "secret")
    key_info = PwsQueryInfo(["name"])
    assert item.make_id(key_info) == "name"
    key_info = PwsQueryInfo(["name", "folder", "secret", "name"], "/", False)
    assert item.make_id(key_info) == "name//secret/name"
    key_info = PwsQueryInfo(["name", "folder", "secret", "name"], "/", True)
    assert item.make_id(key_info) == "name//secret/name"
