from os import close
from elftools.elf.elffile import ELFFile
from capstone import *
from typing import *
import io

from label import Label

class Receptor:
    abs32s: List[Label]
    rel32s: List[Label]
    emitted_bytes: List[bytes]
    origin: int
    def __init__(self):
        self.program = []
        self.emitted_bytes = []
        self.rel32s = []
        self.origin = 0
        self.abs32s = []

    def emit_rel32(self, label : Label):
        self.rel32s.append(label)
    def emit_origin(self, origin: int):
        self.origin = origin
    def emit_abs32(self, abs32 : Label):
        self.abs32s.append(abs32)
    def emit_bytes(self, program : bytes):
        self.emitted_bytes.append(program)

class Addresses:
    data = b"" # data
    receptor: Receptor
    def __init__(self, data : bytes, receptor: Receptor):
        self.data = data
        self.receptor = receptor

    def _get_jmp_call(self, p : int, end_ptr : int) -> Optional[Label]:
        rel32 = None
        is_rip_relative = False
        if (p + 5 <= end_ptr):
            # jmp rel32 : 0xE8
            # call rel32: 0xE9
            if self.data[p] == 0xE8 or self.data[p] == 0xE9:
                rel32 = self.data[p+1:p+5]

        if (p + 6 <= end_ptr):
            # jcc long form 0x0Ff
            if self.data[p] == 0x0F and (self.data[p+1] & 0xF0) == 0x80:
                if self.data[p+1] != 0x8A and self.data[p+1] != 0x8B:
                    rel32 = self.data[p+2:p+6]
                    # not JPE / JPO

            # === x64 only ===
            # ff 15: call qword ptr
            # ff 25: jmp qword ptr
            elif ((self.data[p] == 0xFF and (self.data[p+1] in (0x15, 0x25))) or self.data[p] in (0x89, 0x8B, 0x8D) and (self.data[p+1] & 0xC7 == 0x05)):
                rel32 = self.data[p+2:p+6]
                is_rip_relative = True

        if (p + 7 <= end_ptr):
            if (self.data[p] & 0xF2) == 0x40 or (self.data[p] & 0xF2 == 0x66) and (self.data[p+1] in [0x89, 0x8B, 0x8D]) and (self.data[p+2] & 0xC7 == 0x05):
                rel32 = self.data[p+3:p+7]
                is_rip_relative = True

        if rel32:
            label = Label(int.from_bytes(rel32, 'little'))
            return label
        else:
            return None

    def treat_rel32(self, rel32 : int):
        if not rel32:
            return None

        #  todo adjust_pointer_to_rva
        #rel32_rva = rel32 - adjust_pointer_to_rva
        # is there an abs32 reloc, overlapping the candidate?
        return rel32

    def get_rel32(self):
        p = 0 # start_offset
        end_pointer = 0
        while p < end_pointer:
            rel32 = self._get_jmp_call(p, 100)
            if rel32:
                self.receptor.emit_rel32(rel32)

class Disassembler:
    def __init__(self, fname : str):
        self.fname = fname
        receptor = Receptor()
        self.receptor = receptor

        instrs_all = []
        f = open(self.fname, "rb")
        self.parse_file(f, receptor)
        f.close()

    def is_valid_target_rva(self, rva : int) -> bool:
        if rva == "unassigned":
            return False

        # read of headers
        return False

    def file_offset_to_rva(self, offset: int) -> int:
        # すべての elf section をみてなおす
        # section内部に入っているときは sh_addr + offset - section_begin
        with open(self.fname) as f:
            x = ELFFile(f)

            for section in x.iter_sections():
                section_header = section.header
                section_begin = section_header.sh_offset
                section_end = section_header.sh_size
                if (offset >= section_begin and offset < section_end):
                    return section_header.sh_addr + offset - section_begin


    def rva_to_file_offset(self, rva: int):
        # rva と file offset を見てなおす
        with open(self.fname) as f:
            x = ELFFile(f)

            for section in x.iter_sections():
                section_header = section.header
                section_begin = section_header.sh_offset
                section_end = section_header.sh_size
                return section_header.sh_offset + rva - section_begin

    def check_section(self, rva: int):
        file_offset = self.rva_to_file_offset(rva)
        # TODO sections
        with open(self.fname) as f:
            x = ELFFile(f)

            for section in x.iter_sections():
                section_header = section.header
                start_offset = section_header.sh_offset
                end_offset = start_offset + section_header.sh_size - 5 + 1

    def parse_progbits(self):
        # TODO
        self.receptor.emit_origin(0)
        #next_relocation = section_end
        #if (current_abs_offset != end_abs_offset and next_relocation > current
        pass


        #return receptor

    def _getabs32(self, f : io.BytesIO):
        for section in self.elfprogram.iter_sections():
            section_header = section.header
            start_offset = section_header.sh_offset
            if section_header.sh_type not in ('SHT_REL', 'SHT_RELA'):
                continue

            for reloc in section.iter_relocations():
                # RELOCS
                print(reloc.entry)

                if reloc.entry.r_info_type != 8:
                    continue
                rva = reloc.entry.r_offset
                self.receptor.emit_abs32(rva)


    def parse_file(self, f : io.BytesIO, receptor : Receptor):

        elffile = ELFFile(f)
        symtable = elffile.get_section_by_name('.symtab')
        self.program = f
        self.elfprogram = elffile
        self._getabs32(f)

        file_offset = 0
        abs_offsets = []
        abs32_locations_ = []

        for sym in symtable.iter_symbols():
            f.seek(sym['st_value'])
            code = f.read(sym['st_size'])

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            # modr/m の部分など個別に取り出せるようにする
            md.detail = True
           # instrs = list(filter(lambda x: x.mnemonic in ["call", "jmp"], md.disasm(maincode, 0)))
           #for i in md.disasm(maincode, 0):
           #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

            # instrs_all.append(instrs)
            # rvvs_to_file_offsets
        for section in elffile.iter_sections():
            header = section.header.sh_type
            # 各セクションヘッダを見つつ
            if header == 'SHT_REL':
                addresses = Addresses(code, receptor)
                addresses.treat_rel32(0)
                continue
            if header == 'SHT_PROGBITS':
                self.parse_progbits()
                continue

            receptor.emit_bytes(section.data())
