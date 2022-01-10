# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""CRUD operations on a bitwarden online database with the PwsItem"""

# TODO:
# - support syncing multiple fields
# - support syncing multiple uris (and their match value)
# - support syncing reprompt
# - support syncing identity and secure note

import json
import os
from base64 import b64encode
from logging import getLogger
from subprocess import call, check_call, check_output
from typing import Dict, List, Optional
from uuid import UUID

from dateutil import parser

from .common import (
    LOGGER_NAME,
    PWS_SYNC,
    Key,
    PwsDuplicate,
    PwsNotFound,
    PwsUnsupported,
    to_bool,
)
from .database_cli import PwsDatabaseClient
from .item import PwsItem

# observed item types:
USER_TYPE = 1  # a login item (has inside a login sub-type)
SECURE_NOTE_TYPE = 2
CARD_TYPE = 3
IDENTITY_TYPE = 4

# observed sub-types:
LOGIN_SUBTYPE = 0

# bw get template item
# card_template looks like {
#     "cardholderName" -> "John Doe",
#     "brand" -> "visa",
#     "number" -> "4242424242424242",
#     "expMonth" -> "04",
#     "expYear" -> "2023",
#     "code" -> "123"}
# identity_template looks like {
#     "title" -> "Mr",
#     "firstName" -> "John",
#     "middleName" -> "William",
#     "lastName" -> "Doe",
#     "address1" -> "123 Any St","address2" -> "Apt #123","address3":null,
#     "city" -> "New York","state" -> "NY","postalCode" -> "10001","country" -> "US",
#     "company" -> "Acme Inc.",
#     "email" -> "john@company.com",
#     "phone" -> "5555551234",
#     "ssn" -> "000-123-4567",
#     "name" -> "jdoe",
#     "passportNumber" -> "US-123456789",
#     "licenseNumber" -> "D123-12-123-12333"}

# The REST API is described here:
# https://bitwarden.com/help/article/public-api/
# https://bitwarden.com/help/api/
# It is not clear how to access items though ...


def _check_fields_for_sync(field: Dict[str, str]) -> bool:
    if PWS_SYNC == field.get("name"):
        return to_bool(field.get("value", "false"))
    return False


def _has_sync(obj: Dict) -> bool:
    fields = obj.get("fields", [])
    return 1 == len([f for f in fields if _check_fields_for_sync(f)])


def _key2uuid(key: Key) -> str:
    return str(UUID(bytes=key))


class BitwardenClientWrapper(PwsDatabaseClient):
    """Implements the CRUD operation on an online Bitwarden password database,
    using the Bitwarden client command line tool"""

    def __init__(
        self,
        client_id: str = "",
        client_secret: str = "",
        master_password: str = "",
        ids: Optional[List[str]] = None,
    ):
        super().__init__()
        self._logger = getLogger(LOGGER_NAME)
        self._key_ids = [] if ids is None else ids  # TODO should not use folder,title as default?
        self._env = dict(os.environ)

        self._make_session(client_id, client_secret, master_password)

    def _check_output(
        self,
        cmd: List[str],
        input_value=None,
    ):
        result_json = check_output(cmd, input=input_value, env=self._env)
        return json.loads(result_json)

    def _make_session(
        self,
        client_id: str,
        client_secret: str,
        master_password: str,
    ):
        self.logout()

        if client_id:
            self._env["BW_CLIENTID"] = client_id
        if client_secret:
            self._env["BW_CLIENTSECRET"] = client_secret
        check_call(["bw", "--raw", "login", "--apikey"], env=self._env)
        self._env.pop("BW_CLIENTID", None)
        self._env.pop("BW_CLIENTSECRET", None)

        self._env["BW_MASTER_PASSWORD"] = master_password
        session = check_output(["bw", "--raw", "unlock", "--passwordenv=BW_MASTER_PASSWORD"], env=self._env)
        self._env.pop("BW_MASTER_PASSWORD", None)
        self._env.update(BW_SESSION=session.decode("utf-8"))

    def _list_objects(
        self,
        kind: str = "items",
        match: Optional[str] = None,
        organization_uuid: Optional[str] = None,
    ):
        check_call(["bw", "sync", "--quiet"], env=self._env)
        if match:
            cmd = ["bw", "--raw", "list", kind, "--search", match]
        else:
            cmd = ["bw", "--raw", "list", kind]
        if organization_uuid:
            cmd += ["--organizationid", organization_uuid]
        objects = self._check_output(cmd)
        return objects

    def _get_object(
        self,
        uuid: str,
        kind: str = "item",
    ) -> Optional[Dict]:
        check_call(["bw", "sync", "--quiet"], env=self._env)
        obj = self._check_output(["bw", "--raw", "get", kind, uuid])
        return obj

    def _get_object_name(
        self,
        uuid: Optional[str],
        kind: str,
    ) -> Optional[str]:
        if uuid is None:
            return None
        obj = self._get_object(uuid, kind)
        return None if obj is None else obj.get("name")

    def _create_object(
        self,
        obj: Dict,
        kind: str = "item",
        organization_uuid: Optional[str] = None,
    ) -> Dict:
        object_json = b64encode(bytes(json.dumps(obj), "utf-8"))
        cmd = ["bw", "create", kind]
        if organization_uuid:
            cmd += ["--organizationid", organization_uuid]
        obj = self._check_output(cmd, object_json)
        return obj

    def _edit_object(
        self,
        uuid: str,
        obj: Dict,
        kind: str = "item",
        organization_uuid: Optional[str] = None,
    ) -> Dict:
        object_json = b64encode(bytes(json.dumps(obj), "utf-8"))
        cmd = ["bw", "edit", kind]
        if organization_uuid:
            cmd += ["--organizationid", organization_uuid]
        cmd.append(uuid)
        update = self._check_output(cmd, object_json)
        return update

    def _delete_object(
        self,
        uuid: str,
        kind: str = "item",
        organization_uuid: Optional[str] = None,
    ):
        cmd = ["bw", "delete", kind, uuid]
        if organization_uuid:
            cmd += ["--organizationid", organization_uuid]
        check_call(cmd, env=self._env)

    def _find_uuid(
        self,
        name: Optional[str],
        kind: str,
        create=True,
        organization_uuid: Optional[str] = None,
    ) -> Optional[str]:
        if not name:
            return None
        objects = self._list_objects(kind + "s", name, organization_uuid)
        if not objects and create:
            new_object = {"name": name}
            if organization_uuid:
                new_object["organizationId"] = organization_uuid
            uuid = self._create_object(new_object, kind, organization_uuid)["id"]
        else:
            uuid = None
        # TODO likely multiple objects with the same name are possible, how to handle this?
        return uuid if not objects else objects[0]["id"]

    def _find_folder_uuid(
        self,
        folder: Optional[str],
        create=True,
    ) -> Optional[str]:
        folder = folder.strip("/") if folder else None
        return self._find_uuid(folder, "folder", create)

    def _find_organization_uuid(
        self,
        org: Optional[str],
    ) -> Optional[str]:
        return self._find_uuid(org, "organization", create=False)

    def _find_collection_uuid(
        self,
        collection: Optional[str],
        organization_uuid: str,
        create=True,
    ) -> Optional[str]:
        return self._find_uuid(collection, "org-collection", create, organization_uuid)

    def _object2item(
        self,
        obj: Dict,
    ) -> PwsItem:
        # pylint: disable=too-many-locals
        assert USER_TYPE == obj["type"]

        title = obj.get("name")
        assert title

        folder = self._get_object_name(obj.get("folderId"), "folder")
        note = obj.get("notes")
        org = self._get_object_name(obj.get("organizationId"), "organization")
        fav = obj.get("favorite", False)

        collections = list(
            filter(
                None,
                [self._get_object_name(id, "collection") for id in obj.get("collectionIds", [])],
            )
        )

        fields = obj.get("fields", [])
        # TODO should actually sync all fields
        field = list(filter(lambda f: PWS_SYNC == f.get("name"), fields))
        sync = _check_fields_for_sync(field[0]) if len(field) == 1 else None

        login = obj.get("login")
        if login:
            name = login.get("username")
            secret = login.get("password")
            totp = login.get("totp")
            # TODO should actually sync all uris and their match value
            url = (login.get("uris") or [{"uri": None}])[0]["uri"]
        else:
            name = secret = url = totp = None

        rev = obj.get("revisionDate")
        mtime = parser.parse(rev) if rev else None
        key = UUID(obj["id"]).bytes if "id" in obj else None

        return PwsItem(
            title,
            name,
            secret,
            folder if folder else "",
            note,
            url,
            totp,
            fav,
            org,
            collections if collections else None,
            sync,
            mtime,
            key,
        )
        # pylint: enable=too-many-locals

    def _prevent_duplicates(
        self,
        new_item: PwsItem,
    ):
        use_folder = "folder" in self._key_ids
        use_title = "title" in self._key_ids
        use_name = "name" in self._key_ids

        cmd = ["bw", "--raw", "list", "items", "--search"]
        cmd.append(new_item.title if use_title else new_item.name)

        if use_folder:
            folder_uuid = self._find_folder_uuid(new_item.folder, create=False)
            cmd += ["--folderid", folder_uuid if folder_uuid else "null"]

        for old_item in self._check_output(cmd):
            match_cnt = 0
            if use_title and new_item.title == old_item["name"]:
                match_cnt += 1
            if use_name:
                login = old_item["login"]
                if isinstance(login, dict) and new_item.name == login.get("username", None):
                    match_cnt += 1
            if use_folder:
                old_item_folder_name = self._get_object_name(old_item.get("folderId"), kind="folder")
                if new_item.folder == old_item_folder_name:
                    match_cnt += 1
            if match_cnt == len(self._key_ids):
                raise PwsDuplicate()

    def logout(self):
        """Lock and logout from the online Bitwarden password database"""
        getLogger("pwsync").info("logout!")
        call(["bw", "--quiet", "lock"])  # ignore failures (e.g. locked already?)
        call(["bw", "--quiet", "logout"])  # ignore failures (e.g. already out?)

    def create(
        self,
        item: PwsItem,
    ) -> PwsItem:
        """creates a Bitwarden item based on given item"""
        self._prevent_duplicates(item)

        folder_uuid = self._find_folder_uuid(item.folder, create=True)
        uris = [{"uri": item.url}] if item.url else []
        login = {
            "username": item.name,
            "password": item.secret,
            "totp": item.totp,
            "uris": uris,
        }

        org_uuid = self._find_organization_uuid(item.organization)

        # TODO cli cannot create item with collection
        # bw edit item-collections <id>

        collection_id_uuids = (
            (
                list(
                    filter(
                        None,
                        [
                            self._find_collection_uuid(collection, org_uuid, create=True)
                            for collection in (item.collections or [])
                        ],
                    )
                )
                or None
            )
            if org_uuid
            else None
        )

        fields = None if item.sync is None else [{"name": PWS_SYNC, "value": str(item.sync)}]

        obj = {
            "organizationId": org_uuid,
            "collectionIds": collection_id_uuids,
            "folderId": folder_uuid,
            "type": USER_TYPE,
            "name": item.title,
            "notes": item.note,
            "favorite": item.favorite,
            # TODO support "reprompt"?
            "login": login,
            "fields": fields,
            "secureNote": None,
            "card": None,
            "identity": None,
        }
        new_obj = self._create_object(obj)
        new_item = self._object2item(new_obj)

        return new_item

    def read(
        self,
        key: Optional[Key] = None,
        sync_flag: Optional[bool] = None,
    ) -> List[PwsItem]:
        """reads Bitwarden object(s) with given optional key and sync flag"""
        objects = self._list_objects() if key is None else [self._get_object(_key2uuid(key))]

        if sync_flag:
            return [self._object2item(o) for o in objects if _has_sync(o)]

        return [self._object2item(o) for o in objects]

    def update(
        self,
        key: Key,
        item: PwsItem,
    ) -> PwsItem:
        """updates a Bitwarden object with given key,
        based on the values in given item"""

        # pylint: disable=too-many-branches
        uuid_str = _key2uuid(key)
        obj = self._get_object(uuid_str)
        if obj is None:
            raise PwsNotFound
        current_item = self._object2item(obj)

        del obj["id"]
        del obj["revisionDate"]
        update_login = obj["login"]

        if item.title != current_item.title:
            obj["name"] = item.title
        if item.folder != current_item.folder:
            obj["folderId"] = self._find_folder_uuid(item.folder, create=True)
        if item.note != current_item.note:
            obj["notes"] = item.note
        if item.favorite != current_item.favorite:
            obj["favorite"] = item.favorite
        if item.sync != current_item.sync:
            # TODO manage multiple fields, not just one
            value = str(item.sync) if item.sync is not None else None
            obj["fields"] = [{"name": PWS_SYNC, "value": value}]
        if item.organization != current_item.organization:
            raise PwsUnsupported("unsupported organization update")
            # TODO how to change the organization with bw cli tool?
            # This does not work: obj["organizationId"] = self._find_organization_uuid(item.organization)
        if (
            isinstance(item.collections, list)
            and isinstance(current_item.collections, list)
            and set(item.collections) != set(current_item.collections)
        ) or (item.collections != current_item.collections):
            raise PwsUnsupported("unsupported collections update")
            # TODO how to change the collection with bw cli tool?
            # This does not work:
            # org_uuid = self._find_organization_uuid(item.organization)
            # print(f"old collections: {obj['collectionIds']}")
            # obj["collectionIds"] = (
            #     list(filter(None, [
            #         self._find_collection_uuid(collection, org_uuid, create=True)
            #         for collection in (item.collections or [])
            #     ],))
            # or None)
        if item.name != current_item.name:
            update_login["username"] = item.name
        if item.secret != current_item.secret:
            update_login["password"] = item.secret
        if item.totp != current_item.totp:
            update_login["totp"] = item.totp
        if item.url != current_item.url:
            # TODO do not replace multipe uri with one
            update_login["uris"] = [{"uri": item.url}] if item.url else []
        # pylint: enable=too-many-branches

        updated_object = self._edit_object(uuid_str, obj, kind="item")
        updated_item = self._object2item(updated_object)
        return updated_item

    def delete(
        self,
        key: Key,
    ) -> PwsItem:
        """deletes the Bitwarden object with given key"""
        uuid = _key2uuid(key)
        obj = self._get_object(uuid)
        if obj is None:
            raise PwsNotFound(uuid)
        item = self._object2item(obj)
        self._delete_object(uuid)
        return item
