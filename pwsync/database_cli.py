# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""Abstract CRUD operations with the PwsItem that specific password databases need to implement"""

from abc import ABC, abstractmethod
from typing import List, Optional

from .common import Key, PwsUnsupported
from .item import PwsItem


class PwsDatabaseClient(ABC):
    """Define abstract CRUD operations on a password database client"""

    @abstractmethod
    def create(self, item: PwsItem) -> PwsItem:
        """create a password entry in the database, based on given item"""
        raise PwsUnsupported("PwsDatabaseClient.create")

    @abstractmethod
    def read(self, key: Optional[Key] = None, sync_flag: Optional[bool] = None) -> List[PwsItem]:
        """read a password entry from the database, based on given key or all entries,
        filter entries base on given sync_flag"""
        raise PwsUnsupported("PwsDatabaseClient.read")

    @abstractmethod
    def update(
        self,
        key: Key,
        item: PwsItem,
    ) -> PwsItem:
        """update the password entry with given key,
        based on the values in given item"""
        raise PwsUnsupported("PwsDatabaseClient.update")

    @abstractmethod
    def delete(self, key: Key) -> PwsItem:
        """delete a password entry from the database, based on given key"""
        raise PwsUnsupported("PwsDatabaseClient.delete")
