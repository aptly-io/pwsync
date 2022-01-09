# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""A PwsItem dataset from loading a password database contents"""

from logging import getLogger

from diffsync import DiffSync

from .common import FOLDER, LOGGER_NAME, NAME, PwsQueryInfo
from .database_cli import PwsDatabaseClient
from .model import Credential


class PasswordDataset(DiffSync):
    """Load credentials from a database"""

    top_level = ["credential"]
    credential = Credential

    def __init__(self, name: str, query_info: PwsQueryInfo, client: PwsDatabaseClient):
        super().__init__(name)
        self._logger = getLogger(LOGGER_NAME)
        self._query_info = query_info
        self.client = client

    def _validate(self, item) -> bool:
        for prop in set(self._query_info.ids + [NAME]) - set([FOLDER]):
            if not getattr(item, prop):
                self._logger.error("item (%s) has empty key_id (%s)", item, prop)
                return False
        return True

    def load(self):

        for item in self.client.read(None, self._query_info.sync):

            # TODO move validation elsewhere
            if not self._validate(item):
                continue

            cred = Credential(
                id=item.make_id(self._query_info),
                title=item.title,
                folder=item.folder,
                name=item.name,
                secret=item.secret,
                note=item.note,
                url=item.url,
                totp=item.totp,
                favorite=item.favorite,
                organization=item.organization,
                collections=item.collections,
                item=item,
            )

            self.add(cred)
