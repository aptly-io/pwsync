# A Password synchronization tool

> WIP (need to commit actual synchronize code)

The _pwsync_ is a low level command line tool that synchronizes _password databases_.

`pwsync` grew from a personal need to simplify the usage of credentials with online service
(e.g. for web shops, banks, cloud services, ...) on different platforms (Ubuntu, iPad, Android mobile, ...).
Keepass feels outdated for such use-cases. 
Bitwarden is a better solution
thanks to its [browser extension](https://bitwarden.com/help/article/getting-started-browserext/).
Due to this personal usage, `pwsync` only supports 
[_Keepass_](https://keepass.info/) database files
and [_Bitwarden_](https://bitwarden.com/) online database.
Feel free to add support for other cloud password service if you know their (public) REST API.

A limited number of password database features are supported (_the lowest common denominator_):

- a hierarchical classification folder/group
- a credential's title/description
- a username
- a secret/password
- a (per credential) note
- one url (without matching capabilities)
- a one time pass code (_TOTP_)
- a favorite flag
- an organization (required when using collections)
- multiple collections
- a specific _sync_ flag that, if missing, will ignore a password database entry during synchronization

Support for fields/properties, icons, expiration date, creation of organizations,
changes on a credential's collection set, reprompt, 
multiple urls and matching pattern, privately hosted Bitwarden ... is missing.

## Usage

> It is very important to familarize oneself with `pwsync` first!
> Use the toy Keepass password database files in the `demo` directory (their passphrase is `pw`).

```bash
# main use-case: synchronize changes from a local Keepass database to an online Bitwarden database.
pwsync --from demo/from.kdbx --to bitwarden

# synchronize between the 2 toy Keepass password database files
export PWS_FROM_PASSWORD="pw"  # Dont store your real passphrase in a shell variable!
export PWS_TO_PASSWORD="pw"  # Repeat: do not use this technique for your real passphrase!
pwsync --from demo/from.kdbx --to demo/to.kdbx  # backup into a "to.kdbx.backup" first!

# a description of all options
pwsync -h
```

## Installation

`pwsync` depends on the [_Bitwarden command line client_](https://bitwarden.com/help/article/cli/) tool.
This tool and its installation description is [here](https://bitwarden.com/help/article/cli/#download-and-install).

```bash
# clone the `pwsync` repo locally
git clone https://github.com/aptly-io/pwsync.git
cd pwsync
```

### As user

```bash
python3 -m pip install .
```

### As developer

(this script should work on a vanila Ubuntu 20.04)

```bash
sudo apt install -y --upgrade git build-essential python3.8-venv
python3.8 -m venv .venv
. .venv/bin/activate

# for development (code formatting, linting, testing)
python -m pip install .[dev]

# for building a distribution
python -m pip intall .[build]
```

### Development

```bash
# format the source code (configuration in pyproject.toml)
python -m black pwsync/*.py tests/*.py

# linting and source code analysis
python -m pylama pwsync/*.py

# tests with an xml coverage report
pytest -s -vvv --cov=pwsync --cov-report=xml:cov.xml tests

# for distribution
python -m build
```

## Technical details

The supported password databases use different technology and implementation:
Keepass is file based while Bitwarden is a cloud service.
To recognize equivalent password entries between the databases,
`pwsync` identifies entries by certain property value(s).
E.g. by default the _folder_ and _title_ property values are used.
(this can be customized with the `--id` command line option).

The synchronization goes in 1 direction:
only the `to` database could get modified due to differences with the `from` database.
There are 3 modification types:
- create: adds a new password entry in the `to` database because it exists only in the `from` database.
- delete: removes an entry from the `to` database because it does not exist in the `from` database.
- update: changes an entry in the `to` database because it is different for the equivalent entry in the `from` database.

An update is a _conflict_ when the `to` password entry has a more recent modification time than
its equivalent entry in the `from` database.
Conflicts are skipped by `pwsync`; one has to manually address these.

> Changing the property value used for password entry identification (e.g. the _title_) in one database,
causes a create/delete modification!

To synchronize, pwsync depends on:
- The python [_diffsync_](https://pypi.org/project/diffsync/) module: determines the differences between two password databases.
- The python [_pykeepass_](https://pypi.org/project/pykeepass/) module: modifies a Keepass_ file.
- Bitwarden's official(?) [_command line client_](https://bitwarden.com/help/article/cli/): modifies a Bitwarden online password database.

## License

`pwsync` is necessarily GPL3 since it (currently) depends upon the GPL3 python module `pykeepass`.

Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)
