# -*- coding: utf-8 -*-

from collections import namedtuple
from typing import Iterable, Optional

import ida_funcs
import ida_idaapi
import ida_xref
import idautils
import idc
from idadex import ea_t


StringInfo = namedtuple("StringInfo", ["address", "content"])


def get_func_arg_count(ea: ea_t) -> int:
    return ida_funcs.get_func(ea).regargqty


def get_segment_ea(segment_name: str) -> Optional[int]:
    for seg in idautils.Segments():
        if idc.get_segm_name(seg) == segment_name:
            return idc.get_segm_start(seg)
    return None


def get_cstrings():
    seg_start = get_segment_ea('__cstring')
    seg_end = idc.get_segm_end(seg_start)
    for string in idautils.Strings():
        # filter out strings that are not in the __cstring section
        if seg_start <= string.ea < seg_end:
            yield StringInfo(string.ea, str(string))


def get_xrefs(ea: ea_t) -> Optional[Iterable[ea_t]]:
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
    seg_start = get_segment_ea("__text")
    seg_end = idc.get_segm_end(seg_start)
    unique_function_names = set()
    # FIXME: If a string is NOT unique we can't use it as an anchor 
    # (also should I look for non-cstring strings; maybe __const strings?)
    unique_anchor_strings = set()

    sigs = {}

    print("🔍 Looking for single references to strings")
    for cstr in get_cstrings():
        # print(f'👀 for XREFs to 0x{s.address:x}: "{repr(s.content)}"')
        xrefs = get_xrefs(cstr.address)
        if xrefs is not None and len(xrefs) == 1:
            if repr(cstr.content) in unique_anchor_strings:
                print(f"Skipping duplicate string: {cstr.content}")
                continue
            unique_anchor_strings.add(repr(cstr.content))
            if xrefs[0] < seg_start or xrefs[0] > seg_end:
                continue
            func_name = idc.get_func_name(xrefs[0])
            if func_name.startswith("sub_F"):
                continue
            args = get_func_arg_count(xrefs[0])
            if func_name:
                unique_function_names.add(func_name)
            if func_name not in sigs:
                sigs[func_name] = {"args": args, "anchors": []}
            sigs[func_name]["anchors"].append(repr(cstr.content))
            # print(f'0x{xrefs[0]:x}: {func_name}(args: {args}) -> "{repr(s.content)}"')
    print("✅ Done looking for single references to strings")

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
