# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""setup for development and installation"""

from setuptools import find_packages, setup

# The complexity of versioning
# https://pythonrepo.com/repo/pypa-setuptools_scm-python-build-tools

with open("README.md", "r", encoding="utf-8") as fp:
    long_description = fp.read()

setup(
    name="pwsync",
    license="GPL3",
    license_files=("LICENSE",),
    author="Francis Meyvis",
    author_email="pwsync@mikmak.fun",
    description="Synchronize password databases",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aptly-io/pwsync",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",  # TODO test on other OSes
        "Topic :: Utilities",
        "Natural Language :: English",
        "Environment :: Console",
    ],
    python_requires=">=3.7.0",
    packages=find_packages(),
    install_requires=[
        "pykeepass==4.0.1",
        "diffsync==1.4.2",
        "prompt-toolkit==3.0.28",
    ],
    extras_require={
        "dev": [
            "black",
            "pylama[all]",
            "pytest",
            "pytest-cov",
            "pytest-mock",
            "pytz",
            "types-python-dateutil",
            "types-pytz",
            "pre-commit",
        ],
        "build": [
            "setuptools>=45.0",
            "wheel",
            "build",
            "twine",
        ],
    },
    entry_points={
        "console_scripts": ["pwsync=pwsync.main:main"],
    },
)
