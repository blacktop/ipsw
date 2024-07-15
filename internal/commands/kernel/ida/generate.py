# -*- coding: utf-8 -*-

from collections import Counter
from typing import Iterable, Optional

import ida_funcs
import ida_idp
import ida_ua
import ida_idaapi
import ida_xref
import idautils
import idc
from idadex import ea_t


class Section:
    def __init__(self, name, segname, addr, size, offset, align, reloff, nreloc, flags):
        self.name = name
        self.segname = segname
        self.addr = addr
        self.size = size
        self.offset = offset
        self.align = align
        self.reloff = reloff
        self.nreloc = nreloc
        self.flags = flags


class Segment:
    def __init__(self, name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize
        self.maxprot = maxprot
        self.initprot = initprot
        self.nsects = nsects
        self.flags = flags
        self.sections = []


class MachO:
    def __init__(self, cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags):
        self.cpu_type = cpu_type
        self.cpu_subtype = cpu_subtype
        self.file_type = file_type
        self.ncmds = ncmds
        self.sizeofcmds = sizeofcmds
        self.flags = flags
        self.segments = []


def get_macho_header_info():
    start_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    macho_magic = idc.get_wide_dword(start_ea)

    if macho_magic != 0xFEEDFACE and macho_magic != 0xFEEDFACF:
        print("This is not a Mach-O binary.")
        return None

    cpu_type = idc.get_wide_dword(start_ea + 4)
    cpu_subtype = idc.get_wide_dword(start_ea + 8)
    file_type = idc.get_wide_dword(start_ea + 12)
    ncmds = idc.get_wide_dword(start_ea + 16)
    sizeofcmds = idc.get_wide_dword(start_ea + 20)
    flags = idc.get_wide_dword(start_ea + 24)

    macho = MachO(cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags)
    parse_segments_and_sections(start_ea, ncmds, macho)
    return macho


def parse_segments_and_sections(start_ea, ncmds, macho):
    offset = 28 if idc.get_wide_dword(start_ea) == 0xFEEDFACE else 32
    ea = start_ea + offset

    for _ in range(ncmds):
        cmd = idc.get_wide_dword(ea)
        cmdsize = idc.get_wide_dword(ea + 4)

        if cmd == 0x1 or cmd == 0x19:  # LC_SEGMENT (32-bit) or LC_SEGMENT_64 (64-bit)
            segname = idc.get_strlit_contents(ea + 8, 16, idc.STRTYPE_C).decode("utf-8")
            vmaddr = idc.get_qword(ea + 24) if cmd == 0x19 else idc.get_wide_dword(ea + 24)
            vmsize = idc.get_qword(ea + 32) if cmd == 0x19 else idc.get_wide_dword(ea + 28)
            fileoff = idc.get_qword(ea + 40) if cmd == 0x19 else idc.get_wide_dword(ea + 32)
            filesize = idc.get_qword(ea + 48) if cmd == 0x19 else idc.get_wide_dword(ea + 36)
            maxprot = idc.get_wide_dword(ea + 52) if cmd == 0x19 else idc.get_wide_dword(ea + 40)
            initprot = idc.get_wide_dword(ea + 56) if cmd == 0x19 else idc.get_wide_dword(ea + 44)
            nsects = idc.get_wide_dword(ea + 64) if cmd == 0x19 else idc.get_wide_dword(ea + 48)
            flags = idc.get_wide_dword(ea + 68) if cmd == 0x19 else idc.get_wide_dword(ea + 52)

            segment = Segment(
                segname,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                flags,
            )

            section_offset = ea + (72 if cmd == 0x19 else 56)
            for _ in range(nsects):
                sectname = idc.get_strlit_contents(section_offset, 16, idc.STRTYPE_C).decode("utf-8")
                segname = idc.get_strlit_contents(section_offset + 16, 16, idc.STRTYPE_C).decode("utf-8")
                addr = idc.get_qword(section_offset + 32) if cmd == 0x19 else idc.get_wide_dword(section_offset + 32)
                size = idc.get_qword(section_offset + 40) if cmd == 0x19 else idc.get_wide_dword(section_offset + 36)
                offset = idc.get_wide_dword(section_offset + 48)
                align = idc.get_wide_dword(section_offset + 52)
                reloff = idc.get_wide_dword(section_offset + 56)
                nreloc = idc.get_wide_dword(section_offset + 60)
                flags = idc.get_wide_dword(section_offset + 64)

                section = Section(sectname, segname, addr, size, offset, align, reloff, nreloc, flags)
                segment.sections.append(section)

                section_offset += 80 if cmd == 0x19 else 68

            macho.segments.append(segment)

        ea += cmdsize


def get_section_by_name(segment_name: str, section_name: str):
    macho = get_macho_header_info()
    if macho is None:
        return None, None
    for segment in macho.segments:
        if segment.name == segment_name:
            for section in segment.sections:
                if section.name == section_name:
                    return int(section.addr), int(section.addr + section.size)
    return None, None


def get_func_start(ea: ea_t) -> Optional[ea_t]:
    return ida_funcs.get_func(ea).start_ea


def get_func_end(ea: ea_t) -> int:
    return ida_funcs.get_func(ea).end_ea


def get_func_arg_count(ea: ea_t) -> int:
    return ida_funcs.get_func(ea).regargqty


def get_unique_cstrings(segment: str, section: str) -> Iterable[idautils.Strings]:
    strings = []
    start, end = get_section_by_name(segment, section)
    print(f"🔍 Searching for unique strings in {segment}.{section} section:\n    - 0x{start:x}-0x{end:x}")
    for string in idautils.Strings():
        # filter out strings that are not in the section
        if start <= string.ea < end:
            strings.append(string)
    # Count the occurrences of each content
    counts = Counter(str(info) for info in strings)
    # Filter StringItem objects that have unique content
    unique_strings = [info for info in strings if counts[str(info)] == 1]
    print(f"    🧵 Found {len(strings)} strings ({len(unique_strings)} unique)")
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


def get_caller(start_ea: ea_t):
    loaded_register = None
    string_value = None
    ea = start_ea

    # print(f"👀👀👀 Look for caller using string at 0x{start_ea:x}")
    end_ea = idc.get_func_attr(start_ea, idc.FUNCATTR_END)

    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        # Failed to decode instruction
        return None

    if insn.get_canon_mnem() != "ADRL":
        return None

    # print("FOUND ADRL")

    # Check if the instruction loads a string into a register
    # https://hex-rays.com/products/ida/support/idapython_docs/ida_ua.html#ida_ua.op_t
    if insn.ops[1].type == idc.o_imm:
        str_ea = insn.ops[1].value
        string_value = idc.get_strlit_contents(str_ea)
        if string_value:
            loaded_register = insn.ops[0].reg
            # print(f"String '{string_value.decode()}' loaded into {ida_idp.get_reg_name(loaded_register, 8)} at {ea:#x}")

    ea = idc.next_head(ea, end_ea)
    if not ida_ua.decode_insn(insn, ea):
        # Failed to decode instruction
        return None

    if insn.get_canon_mnem() != "BL":
        return None

    # print("🎉 FOUND BL")

    if insn.ops[0].type == idc.o_near:
        caller_ea = insn.ops[0].addr
        # print(f"Caller address: {caller_ea:#x}")
        caller_name = idc.get_func_name(caller_ea)
        # print(f"Caller name: {caller_name}")
        return caller_name

    return None
    # while ea < end_ea:
    #     if not ida_ua.decode_insn(insn, ea):
    #         # Failed to decode instruction
    #         break

    #     # Check if the instruction is a call and uses the loaded register
    #     if insn.itype == idaapi.NN_call and loaded_register is not None:
    #         print("FOUND CALL INSTRUCTION AFTER ADRL")
    #         if insn.ops[0].type == idaapi.o_reg and insn.ops[0].reg == loaded_register:
    #             called_func_ea = insn.ops[0].addr
    #             func_name = idc.get_func_name(called_func_ea)
    #             print(
    #                 f"Function {func_name} called using register {idc.get_reg_name(loaded_register, 4)} after loading string '{string_value.decode()}' at {ea:#x}"
    #             )
    #             return func_name

    #     ea = idc.next_head(ea, end_ea)
    #     print(f"Next head: {ea:#x}")

    # print("No function call found after string load")
    # return None


def get_single_ref_funcs() -> {}:
    functions_with_single_xref = {}
    for func_ea in idautils.Functions():
        xrefs = list(idautils.CodeRefsTo(func_ea, 0))
        if len(xrefs) == 1:
            func_name = idc.get_func_name(func_ea)
            xref_name = idc.get_func_name(xrefs[0])
            if func_name.startswith("sub_F"):
                continue
            if func_name not in functions_with_single_xref:
                functions_with_single_xref[func_name] = xref_name
    return functions_with_single_xref


def find_single_refs() -> None:
    seg_start, seg_end = get_section_by_name("__TEXT_EXEC", "__text")
    unique_function_names = set()
    unique_caller_names = set()
    unique_callie_names = set()

    sigs = {}
    single_ref_funcs = get_single_ref_funcs()
    sections = [("__TEXT", "__cstring"), ("__TEXT", "__os_log"), ("__KLDDATA", "__cstring")]

    print("\n\n===============================================================================================")
    print("=========================[🔍 Looking for single references to strings]=========================")
    print("===============================================================================================\n")
    for segname, sectname in sections:
        for cstr in get_unique_cstrings(segname, sectname):
            # print(f'👀 for XREFs to 0x{s.address:x}: "{repr(s.content)}"')
            xrefs = get_xrefs(cstr.ea)
            if xrefs is not None and len(xrefs) == 1:
                if "\\x" in repr(str(cstr)):
                    print(f"      ⚠️ Skipping non-ascii string: {repr(str(cstr))[:40]}")
                    continue
                if xrefs[0] < seg_start or xrefs[0] > seg_end:
                    continue
                func_name = idc.get_func_name(xrefs[0])
                if func_name.startswith("sub_F"):
                    continue  # Skip unnamed functions
                args = get_func_arg_count(xrefs[0])
                caller = get_caller(xrefs[0])
                if caller:
                    unique_caller_names.add(caller)
                callie = None
                if func_name in single_ref_funcs:
                    caller = single_ref_funcs[func_name]
                    unique_callie_names.add(caller)
                if func_name:
                    unique_function_names.add(func_name)
                if func_name not in sigs:
                    sigs[func_name] = {"args": args, "caller": caller, "anchors": []}
                sigs[func_name]["anchors"].append(repr(str(cstr)))
                # print(f'0x{xrefs[0]:x}: {func_name}(args: {args}) -> "{repr(s.content)}"')
    print("\n✅ Done ========================================================================================\n")

    # Output unique function names
    print("[STATS]")
    print(f"\nUnique Function Names: {len(unique_function_names)}")
    print(f"Unique Callie Names:   {len(unique_callie_names)}")
    print(f"Unique Caller Names:   {len(unique_caller_names)}")
    total = len(unique_function_names) + len(unique_callie_names) + len(unique_caller_names)
    print("---------------------------")
    print(f"TOTAL 🎉:              {total}\n")
    print("===============================================================================================\n")
    # for func_name in sorted(unique_caller_names):
    #     print(func_name)

    with open("/tmp/sigs.pkl", "w", encoding="utf-8") as f:
        f.write('amends "../pkl/Symbolicator.pkl"\n\n')
        f.write(f"total = {total}\n\n")
        f.write("signatures {\n")
        for func_name, sig in sigs.items():
            caller = sig["caller"] if sig["caller"] else "?"
            try:
                f.write("    new {\n")
                f.write(f'        args = {sig["args"]}\n')
                f.write("        anchors {\n")
                for anchor in sig["anchors"]:
                    f.write(f"            {fix_string(anchor)}\n")
                f.write("        }\n")
                f.write(f'        symbol = "{func_name}"\n')
                f.write(f'        prototype = ""\n')
                f.write(f'        caller = "{caller}"\n')
                f.write("    }\n")
            except Exception as e:
                print(f"Error: for {func_name} {e}")
        f.write("}")


if __name__ == "__main__":
    find_single_refs()
    qexit(0)
