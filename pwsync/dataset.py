# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""A PwsItem dataset from loading a password database contents"""

from logging import getLogger

from diffsync import DiffSync

from .common import LOGGER_NAME, PwsQueryInfo
from .model import Credential


class PasswordDataset(DiffSync):
    """Load credentials from a database"""

    top_level = ["credential"]
    credential = Credential

    def __init__(self, name: str, query_info: PwsQueryInfo, client):
        super().__init__(name)
        self.logger = getLogger(LOGGER_NAME)
        self.query_info = query_info
        self.client = client

    def _validate(self, item):
        for prop in self.query_info.ids:
            if not getattr(item, prop):
                self.logger.error("item has empty key_id (%s) value: %s", prop, item)
                continue

    def load(self):

        for item in self.client.read(None, self.query_info.sync):

            # TODO move validation elsewhere, add proper logging
            self._validate(item)

            cred = Credential(
                id=item.make_id(self.query_info),
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
