# Copyright 2022 Francis Meyvis (pwsync@mikmak.fun)

"""interactive synchronize using the console"""

import sys
from difflib import SequenceMatcher
from typing import List, Optional

from prompt_toolkit import HTML
from prompt_toolkit import print_formatted_text as print_ft
from prompt_toolkit import prompt
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.validation import ValidationError, Validator

from .common import (
    COLLECTIONS,
    FAVORITE,
    FOLDER,
    NAME,
    NOTE,
    ORGANIZATION,
    SECRET,
    SYNC,
    TOTP,
    URL,
    PwsQueryInfo,
    PwsUnsupported,
    RunOptions,
)
from .database_cli import PwsDatabaseClient
from .dataset import PasswordDataset
from .item import PwsItem
from .sync import PwsDiffElement, PwsSyncer

STYLE = Style.from_dict(
    {
        "data": "bold",
        "info": "italic",
    }
)

PROP_ORDER = [NAME, SECRET, NOTE, URL, TOTP, FAVORITE, ORGANIZATION, COLLECTIONS, SYNC]


# inspired by https://stackoverflow.com/a/788780
def _highlight_diff(old: str, new: str):
    diff_sequencer = SequenceMatcher(None, old, new)
    new_ft, old_ft = [], []
    for opcode, old0, old1, new0, new1 in diff_sequencer.get_opcodes():
        if opcode == "equal":
            new_ft.append(diff_sequencer.a[old0:old1])
            old_ft.append(diff_sequencer.a[old0:old1])
        elif opcode == "insert":
            old_ft.append(_markup(diff_sequencer.b[new0:new1], "ansigreen"))
        elif opcode == "delete":
            new_ft.append(_markup(diff_sequencer.a[old0:old1], "ansired"))
        elif opcode == "replace":
            new_ft.append(_markup(diff_sequencer.a[old0:old1], "ansired"))
            old_ft.append(_markup(diff_sequencer.b[new0:new1], "ansigreen"))
        else:
            raise PwsUnsupported(f"SequenceMatcher opcode: {opcode}")
    return "".join(new_ft), "".join(old_ft)


def _offset_ft(offset: int, string: str) -> str:
    spaces = " " * offset
    return "\n".join([spaces + line for line in string.splitlines()])


def _markup(data: str, markup: str):
    return f"<{markup}>{data}</{markup}>"


def _highlight_propery_values(prop: str, from_item: Optional[PwsItem], to_item: Optional[PwsItem]):

    new_value = str(getattr(from_item, prop, "")) if from_item else ""
    new_value = new_value if new_value else ""  # the case where it property value is present but None
    old_value = str(getattr(to_item, prop, "")) if to_item else ""
    old_value = old_value if old_value else ""

    if prop == SECRET:
        # dont show secrets
        is_longish = False
        if old_value and new_value and old_value != new_value:
            return _highlight_diff("*******", "******* (modified)") + (is_longish,)
        old_value = "*******" if old_value else ""
        new_value = "*******" if new_value else ""
    else:
        is_longish = (
            len(new_value.splitlines()) > 1
            or len(new_value) > 35
            or len(old_value.splitlines()) > 1
            or len(old_value) > 35
        )

    return _highlight_diff(old_value, new_value) + (is_longish,)


def _print_ft_element_header(item: PwsItem, count: int, key_ids: List[str]):
    header = f"    <info>{count}. </info>"
    for key in key_ids:
        if key != FOLDER:
            value = getattr(item, key)
            header += "<info>not available, </info>" if value is None else _markup(value, "data") + "<info>, </info>"
    print_ft(HTML(header), style=STYLE)


def _print_ft_element(
    count: int,
    key_info: PwsQueryInfo,
    section_folder: str,
    props: List[str],
    from_item: Optional[PwsItem],
    to_item: Optional[PwsItem],
) -> str:
    item = from_item if from_item else to_item
    if item is None:
        return section_folder

    folder, tag = (item.folder, "data") if item.folder else ("no-folder ", "info")  # space is on purpose
    if section_folder != folder:
        section_folder = folder
        print_ft(HTML("  " + _markup(section_folder, tag)), style=STYLE)

    _print_ft_element_header(item, count, key_info.ids)

    for prop in [prop for prop in PROP_ORDER if prop in props]:
        old_value, new_value, is_longish = _highlight_propery_values(prop, from_item, to_item)

        old_value = _markup(*(old_value, "data") if to_item and getattr(to_item, prop) else ("no-value", "info"))
        new_value = _markup(*(new_value, "data") if from_item and getattr(from_item, prop) else ("no-value", "info"))

        if is_longish:
            if to_item:
                print_ft(HTML(f"      <info>old {prop:<16}: </info>{_offset_ft(28, old_value).lstrip()}"), style=STYLE)
            if from_item:
                print_ft(HTML(f"      <info>new {prop:<16}: </info>{_offset_ft(28, new_value).lstrip()}"), style=STYLE)
        else:
            if to_item and from_item:
                print_ft(
                    HTML(f"      <info>update {prop:<12}: </info>{old_value}<info> -> </info>{new_value}"),
                    style=STYLE,
                )
            elif from_item and getattr(from_item, prop):
                print_ft(HTML(f"      <info>add {prop:<16}: </info>{new_value}"), style=STYLE)
            elif to_item and getattr(to_item, prop):
                print_ft(HTML(f"      <info>remove {prop:<12}: </info>{old_value}"), style=STYLE)
    return section_folder


def _sync_prompt(kind: str):
    def toolbar():
        return HTML(f"<b>A</b>pply {kind} | <b>S</b>kip {kind} | <b>Q</b>uit synchronization")

    class AnswerValidator(Validator):
        """validates user's input"""

        def validate(self, document):
            text = document.text
            if len(text) < 1 or text[0].lower() not in ["a", "s", "q"]:
                raise ValidationError(message="Unsupported content", cursor_position=0)

    return prompt(
        None, bottom_toolbar=toolbar, validator=AnswerValidator(), completer=WordCompleter(["apply", "skip", "quit"])
    )


def _sync_element(kind: str, element: PwsDiffElement, to_db: PwsDatabaseClient):
    if kind == "update":
        to_update = element.add_props & element.remove_props
        changes = {k: getattr(element.from_item, k) for k in to_update | element.add_props}
        # changes.update({k: None for k in element.remove_props})
        update_item = element.to_item.update(**changes)
        item = to_db.update(element.to_item.key, update_item)
        print(f"update: {item}")
    elif kind == "create":
        item = to_db.create(element.from_item)
        print(f"created: {item}")
    elif kind == "delete":
        item = to_db.delete(element.to_item.key)
        print(f"deleted: {item}")
    else:
        raise PwsUnsupported(f"_sync_element({kind})")


def _sync_section(
    kind: str, query_info: PwsQueryInfo, syncer: PwsSyncer, run_options: RunOptions, to_dataset: PasswordDataset
):
    def _get_key_using_from_item(diff_element: PwsDiffElement):
        return diff_element.from_item.make_id(query_info) if diff_element.from_item else ""

    def _get_key_using_to_item(diff_element: PwsDiffElement):
        return diff_element.to_item.make_id(query_info) if diff_element.to_item else ""

    if kind == "update":
        data = syncer.updates
        key_getter = _get_key_using_from_item
        props_name = "add_props"
    elif kind == "create":
        data = syncer.creates
        key_getter = _get_key_using_from_item
        props_name = "add_props"
    elif kind == "delete":
        data = syncer.deletes
        key_getter = _get_key_using_to_item
        props_name = "remove_props"
    elif kind == "conflict":
        # TODO show modification date/time
        data = syncer.conflicts
        key_getter = _get_key_using_from_item
        props_name = "add_props"
    elif kind == "skipped":
        return  # TODO handle skipped
    elif kind == "unchanged":
        return  # TODO handle skipped

    print_ft(HTML(_markup(f"To {kind}: {len(data)}", "info")), style=STYLE)

    section_folder = ""
    count = 0
    for element in sorted(data, key=key_getter):
        count += 1
        section_folder = _print_ft_element(
            count, query_info, section_folder, getattr(element, props_name), element.from_item, element.to_item
        )

        if run_options.dry_run:
            continue

        if run_options.auto_update and kind == "update":
            _sync_element(kind, element, to_dataset.client)
        elif run_options.auto_create and kind == "create":
            _sync_element(kind, element, to_dataset.client)
        elif kind in ("update", "create", "delete"):
            answer = _sync_prompt(kind)[0].lower()
            if answer == "q":
                sys.exit(0)
            if answer == "s":
                continue
            if answer == "a":
                _sync_element(kind, element, to_dataset.client)


def console_sync(query_info: PwsQueryInfo, syncer: PwsSyncer, run_options: RunOptions, to_dataset: PasswordDataset):
    """synchronize with an interactive console"""

    _sync_section("conflict", query_info, syncer, run_options, to_dataset)
    _sync_section("update", query_info, syncer, run_options, to_dataset)
    _sync_section("create", query_info, syncer, run_options, to_dataset)
    _sync_section("delete", query_info, syncer, run_options, to_dataset)
    _sync_section("skipped", query_info, syncer, run_options, to_dataset)
    _sync_section("unchanged", query_info, syncer, run_options, to_dataset)
