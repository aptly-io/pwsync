# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""interactive synchronize using graphical user interface"""

from .common import PwsUnsupported, RunOptions
from .dataset import PasswordDataset
from .sync import PwsSyncer


def gui_sync(args, syncer: PwsSyncer, run_options: RunOptions, to_dataset: PasswordDataset):
    """synchronize with an graphical user interface"""
    raise PwsUnsupported("--gui")
