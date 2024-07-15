import idc


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
