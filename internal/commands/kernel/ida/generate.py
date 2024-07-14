# -*- coding: utf-8 -*-

from collections import Counter
from typing import Iterable, Optional

import ida_funcs
import ida_idaapi
import ida_xref
import idautils
import idc
from idadex import ea_t


def get_section_by_name(segment_name, section_name):
    """
    Get the start and end address of a specific section in a specific segment.

    Args:
        segment_name (str): The name of the segment.
        section_name (str): The name of the section within the segment.

    Returns:
        tuple: (start_ea, end_ea) if found, else (None, None).
    """
    for seg in idautils.Segments():
        segment = ida_segment.getnseg(seg)
        if segment and ida_segment.get_segm_name(segment) == segment_name:
            for s in ida_segm.get_segm_sections(segment):
                if s.name == section_name:
                    return s.start_ea, s.end_ea
    return None, None


def get_func_arg_count(ea: ea_t) -> int:
    return ida_funcs.get_func(ea).regargqty


def get_segment_ea(segment_name: str) -> Optional[Iterable[int]]:
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == segment_name:
            yield idc.get_segm_start(seg)
    return None


def in_segment(ea: ea_t, segment_name: str) -> bool:
    for seg_start in get_segment_ea(segment_name):
        if seg_start is None:
            return False
        return seg_start <= ea < idc.get_segm_end(seg_start)
    return False


def get_unique_cstrings() -> Iterable[idautils.Strings]:
    strings = []
    start, end = get_section_by_name("__TEXT", "__cstring")
    print(f"🔍 Searching for unique strings in __TEXT.__cstring section: 0x{start:x}-0x{end:x}")
    for string in idautils.Strings():
        # filter out strings that are not in the __cstring or __os_log section
        if in_segment(string.ea, "__cstring") or in_segment(string.ea, "__os_log"):
            strings.append(string)
    # Count the occurrences of each content
    counts = Counter(str(info) for info in strings)
    print(f"🔍 Found {len(strings)} strings")
    # Filter StringItem objects that have unique content
    unique_strings = [info for info in strings if counts[str(info)] == 1]
    print(f"🔍 Found {len(unique_strings)} unique strings")
    return unique_strings


def get_xrefs(ea: ea_t) -> Iterable[ea_t]:
    xrefs = []
    next_ea = ida_xref.get_first_dref_to(ea)
    while next_ea != ida_idaapi.BADADDR:
        xrefs.append(next_ea)
        next_ea = ida_xref.get_next_dref_to(ea, next_ea)
    return xrefs


def fix_string(s):
    if s.startswith("'") and s.endswith("'"):
        s = '"' + s[1:-1].replace('"', '\\"') + '"'
    return s.replace("Couldn't", "Couldn\\\\'t").replace("couldn't", "couldn\\\\'t")


def find_single_refs() -> None:
    seg_start = next(get_segment_ea("__text"))
    seg_end = idc.get_segm_end(seg_start)
    unique_function_names = set()
    # FIXME: If a string is NOT unique we can't use it as an anchor
    # (also should I look for non-cstring strings; maybe __const strings?)
    # unique_anchor_strings = set()

    sigs = {}

    print("🔍 Looking for single references to strings")
    for cstr in get_unique_cstrings():
        # print(f'👀 for XREFs to 0x{s.address:x}: "{repr(s.content)}"')
        xrefs = get_xrefs(cstr.ea)
        if xrefs is not None and len(xrefs) == 1:
            # if repr(str(cstr)) in unique_anchor_strings:
            #     print(f"Skipping duplicate string: {repr(str(cstr)) }")
            #     continue
            # unique_anchor_strings.add(repr(str(cstr)))
            if xrefs[0] < seg_start or xrefs[0] > seg_end:
                continue
            func_name = idc.get_func_name(xrefs[0])
            if func_name.startswith("sub_F"):
                continue  # Skip unnamed functions
            args = get_func_arg_count(xrefs[0])
            if func_name:
                unique_function_names.add(func_name)
            if func_name not in sigs:
                sigs[func_name] = {"args": args, "anchors": []}
            sigs[func_name]["anchors"].append(repr(str(cstr)))
            # print(f'0x{xrefs[0]:x}: {func_name}(args: {args}) -> "{repr(s.content)}"')
    print("✅ Done")

    # Output unique function names
    print(f"\n{len(unique_function_names)}: Unique Function Names\n")
    # for func_name in sorted(unique_function_names):
    #     print(func_name)

    with open("/tmp/sigs.pkl", "w", encoding="utf-8") as f:
        f.write('amends "../pkl/Symbolicator.pkl"\n\n')
        f.write("signatures {\n")
        for func_name, sig in sigs.items():
            try:
                f.write("    new {\n")
                f.write(f'        args = {sig["args"]}\n')
                f.write("        anchors {\n")
                for anchor in sig["anchors"]:
                    f.write(f"            {fix_string(anchor)}\n")
                f.write("        }\n")
                f.write(f'        symbol = "{func_name}"\n')
                f.write(f'        caller = "?"\n')
                f.write("    }\n")
            except Exception as e:
                print(f"Error: for {func_name} {e}")
        f.write("}")


if __name__ == "__main__":
    find_single_refs()
