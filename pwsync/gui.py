# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""interactive synchronize using graphical user interface"""

from .common import PwsUnsupported
from .sync import PwsSyncer


def gui_sync(args, syncer: PwsSyncer, dry_run: bool):
    """synchronize with an graphical user interface"""
    raise PwsUnsupported("--gui")
