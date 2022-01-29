#!/usr/bin/env python3

# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

""" password sync's entry point"""

from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from dataclasses import dataclass
from getpass import getpass
from logging import INFO, FileHandler, basicConfig, getLogger
from os import getenv, path
from time import strftime
from typing import Optional

from .bw_cli_wrapper import BitwardenClientWrapper
from .common import LOGGER_NAME, PwsNotFound, PwsQueryInfo, RunOptions
from .console import console_sync
from .dataset import PasswordDataset
from .gui import gui_sync
from .kp_db_cli import KeepassDatabaseClient
from .sync import PwsSyncer
from .version import __version__


@dataclass
class _AccessInfo:
    identification: str = ""
    secret: str = ""
    master_password: str = ""


def _parse_command_line():
    parser = ArgumentParser(
        description="Synchronise 'from' a password databases 'to' another",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-f",
        "--from",
        required=True,
        help="synchronize from. Specify a Keepass database filename or the keyword 'bitwarden'",
    )

    parser.add_argument(
        "-t",
        "--to",
        required=True,
        help="synchronize to. Only this might be modified (take a backup?). "
        + "Specify a Keepass database filename or the keyword 'bitwarden'",
    )

    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="describe the action then quit without modifications",
    )

    parser.add_argument(
        "--id",
        default="folder,title",
        help="an ordered, comma separated property list, "
        + "used to identify equivalent entries among the from and to password databases",
    )

    parser.add_argument("--id-sep", default=":", help="a separator to separate the id key parts (see --id)")

    parser.add_argument(
        "-a",
        "--sync-all",
        action="store_true",
        help="synchronize all the password database entries. "
        + "By default only entries that have their 'pws_sync' flag attribute set, "
        + "are synchronized; not the whole database",
    )

    parser.add_argument(
        "--from-username",
        help="the identification to access the 'from' password database. "
        + "In case of Bitwarden, this is the client-id. "
        + "Overrides the env. var. PWS_FROM_USERNAME. "
        + "If left empty, it is prompted for on the command line",
    )

    parser.add_argument(
        "--from-secret",
        help="the secret corresponding to the identification (from-username) to access the 'from' password database. "
        + "In case of Bitwarden, this is the client-secret. "
        + "Overrides the env. var. PWS_FROM_SECRET. "
        + "Warning: this is unsafe as command-line options can leak out from the process scope, "
        + "or stored in the shell history buffer, etc. If left empty, it is prompted for on the command line",
    )

    parser.add_argument(
        "--from-master-password",
        help="the password to unlock or decrypt the 'from' password database. "
        + "Overrides the env. var. PWS_FROM_MASTER_PASSWORD. "
        + "Warning: this is unsafe as command-line options can leak out from the process scope, "
        + "or stored in the shell history buffer, etc. If left empty, it is prompted for on the command line",
    )

    parser.add_argument(
        "--to-username",
        help="the identification to access the 'to' password database. "
        + "In case of Bitwarden, this is the client-id. "
        + "Overrides the env. var. PWS_TO_USERNAME. "
        + "If left empty, it is prompted for on the command line",
    )

    parser.add_argument(
        "--to-secret",
        help="the secret corresponding to the identification (to-username) to access the 'to' password database. "
        + "In case of Bitwarden, this is the client-secret. "
        + "Overrides the env. var. PWS_TO_SECRET. "
        + "Warning: this is unsafe as command-line options can leak out from the process scope, "
        + "or stored in the shell history buffer, etc. If left empty, it is prompted for on the command line",
    )

    parser.add_argument(
        "--to-master-password",
        help="the password to unlock or decrypt the 'to' password database. "
        + "Overrides the env. var. PWS_TO_MASTER_PASSWORD. "
        + "Warning: this is unsafe as command-line options can leak out from the process scope, "
        + "or stored in the shell history buffer, etc. If left empty, it is prompted for on the command line",
    )

    parser.add_argument("-U", "--auto-update", action="store_true", help="automatically update all entries")
    parser.add_argument("-C", "--auto-create", action="store_true", help="automatically create all entries")

    parser.add_argument("--gui", action="store_true", help="use a graphical user interface (not implemented)")

    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    parser.add_argument("-l", "--log-level", type=int, default=30, help="logging level")

    parser.add_argument("--log-dir", action="store", default=".", help="log directory")

    args = parser.parse_args()

    # get values from env. vars. if necessary
    if getattr(args, "from") is None:
        setattr(args, "from", getenv("PWS_FROM", None))
    if args.to is None:
        args.to = getenv("PWS_TO", None)

    args.sync = not args.sync_all

    if args.from_username is None:
        args.from_username = getenv("PWS_FROM_USERNAME", None)
    if args.from_secret is None:
        args.from_secret = getenv("PWS_FROM_SECRET", None)
    if args.from_master_password is None:
        args.from_master_password = getenv("PWS_FROM_MASTER_PASSWORD", None)
    if args.to_username is None:
        args.to_username = getenv("PWS_TO_USERNAME", None)
    if args.to_secret is None:
        args.to_secret = getenv("PWS_TO_SECRET", None)
    if args.to_master_password is None:
        args.to_master_password = getenv("PWS_TO_MASTER_PASSWORD", None)
    getLogger(LOGGER_NAME).info(args)

    return args


def _create_bitwarden_dataset(
    name: str,
    query_info: PwsQueryInfo,
    access: _AccessInfo,
) -> PasswordDataset:
    client = BitwardenClientWrapper(access.identification, access.secret, access.master_password, query_info.ids)
    dataset = PasswordDataset(name, query_info, client)
    return dataset


def _create_keepass_dataset(
    name: str,
    query_info: PwsQueryInfo,
    password: Optional[str] = None,
) -> PasswordDataset:
    if password is None:
        password = getpass(f"Password for {name}:")
    client = KeepassDatabaseClient(name, password)
    dataset = PasswordDataset(name, query_info, client)
    return dataset


def _open_password_db(
    query_info: PwsQueryInfo,
    position: str,
    name: str,
    access: _AccessInfo,
):
    if name.lower() in ["bitwarden", "bw"]:
        return _create_bitwarden_dataset(position + name.lower(), query_info, access)
    if path.exists(name):
        return _create_keepass_dataset(name, query_info, access.master_password)
    raise PwsNotFound(name)


def main():
    """entry point for password synchronisation"""

    args = _parse_command_line()

    basicConfig(format="%(asctime)s %(levelname)s:%(message)s", level=INFO)
    logger = getLogger(LOGGER_NAME)
    logger.setLevel(args.log_level)

    file_handler = FileHandler(strftime(path.join(args.log_dir, "pwsync_%Y_%m_%d_%H_%M_%S.log")))
    logger.addHandler(file_handler)
    logger.propagate = False  # do not further propagate to the root handler (stdout)

    query_info = PwsQueryInfo(args.id.split(","), args.id_sep, args.sync)

    access = _AccessInfo(args.from_username, args.from_secret, args.from_master_password)
    from_dataset = _open_password_db(query_info, "from", getattr(args, "from"), access)
    access = _AccessInfo(args.to_username, args.to_secret, args.to_master_password)
    to_dataset = _open_password_db(query_info, "to", args.to, access)
    syncer = PwsSyncer(from_dataset, to_dataset)
    syncer.sync()

    run_options = RunOptions(args.dry_run, args.auto_update, args.auto_create)
    # TODO validate the password database soundness before synchronizing

    if args.gui:
        gui_sync(query_info, syncer, run_options, to_dataset)
    else:
        console_sync(query_info, syncer, run_options, to_dataset)


if __name__ == "__main__":
    main()
