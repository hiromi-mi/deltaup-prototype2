from elftools.elf.elffile import ELFFile
import elftools.elf.sections as sections
#from capstone import *

class Receptor:
    def __init__(self):
        self.program = []
        self.emitted_bytes = []
        self.rel32s = []
        self.abs32s = []

    def emit_rel32(self, label):
        self.rel32s.append(label)
    def emit_abs32(self, abs32):
        self.abs32s.append(abs32)
    def emit_bytes(self, program):
        self.emitted_bytes.append(program)

class Addresses:
    data = b"" # data
    def __init__(self, data):
        self.data = data

    def _get_jmp_call(self, p, end_ptr):
        rel32 = None
        is_rip_relative = False
        if (p + 5 <= end_ptr):
            if self.data[p] == 0xE8 or self.data[p] == 0xE9:
                rel32 = self.data[p+1:p+5]
        
        if (p + 6 <= end_ptr):
            if self.data[p] == 0x0F and (self.data[p+1] & 0xF0) == 0x80:
                if self.data[p+1] != 0x8A and self.data[p+1] != 0x8B: 
                    rel32 = self.data[p+2:p+6]
                    # not JPE / JPO
            elif ((self.data[p] == 0xFF and (self.data[p+1] in [0x15, 0x25])) or self.data[p] in (0x89, 0x8B, 0x8D) and (self.data[p+1] & 0xC7 == 0x05)):
                rel32 = self.data[p+2:p+6]
                is_rip_relative = True
        
        if (p + 7 <= end_ptr):
            if (self.data[p] & 0xF2) == 0x40 or (self.data[p] & 0xF2 == 0x66) and (p[1] in [0x89, 0x8B, 0x8D]) and (p[2] & 0xC7 == 0x05):
                rel32 = self.data[p+3:p+7]
                is_rip_relative = True
        
        return rel32

    def _treat_rel32(self, rel32, adjust_pointer_to_rva):
        if not rel32:
            return None

        #  TODO adjust_pointer_to_rva
        #rel32_rva = rel32 - adjust_pointer_to_rva
        # is there an abs32 reloc, overlapping the candidate?
        return rel32

    def get_rel32(self):
        p = 0 # start_offset
        while p < end_pointer:
            addresses = Addresses()
            addresses._get_jmp_call(p, 100)
            # TODO
            pass

class Disassembler:
    def __init__(self, fname):
        self.fname = fname

    def is_valid_target_rva(rva):
        if rva == "unassigned":
            return False
        
        # read of headers
        return False

    def file_offset_to_rva(offset):
        # すべての ELF Section をみてなおす
        # section内部に入っているときは sh_addr + Offset - section_begin
        for x in sections:
            section_header = SectionHeader(section_id)
            section_begin = section_header.sh_offset
            section_end = section_header.sh_size
            if (offset >= section_begin and offset < section_end):
                return section_header.sh_addr + offset - section_begin
        pass

    def rva_to_file_offset(rvas):
        # RVA と File Offset を見てなおす
        for x in sections:
            section_header = SectionHeader(section_id)
            return section_header.sh_offset + rva - section_begin
        pass

    def check_section(rva):
        file_offset = rva_to_file_offset(rva)
        # TODO sections
        for x in sections:
            section_header = SectionHeader(section_id)
            start_offset = section_header.sh_offset
            end_offset = start_offset + section_header.sh_size - 5 + 1

    def parse_progbits(self):
        # TODO
        emit_origin(origin)
        next_relocation = section_end
        #if (current_abs_offset != end_abs_offset and next_relocation > current
    
    def disassemble(self):
        receptor = Receptor()

        instrs_all = []
        f = open(self.fname, "rb")
        self.parse_file(f, receptor)

        return receptor

    def parse_file(self, f, receptor):
        elffile = ELFFile(f)
        symtable = elffile.get_section_by_name('.symtab')
        self.program = f
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
                addresses = Addresses()
                self._treat_rel32(0, 0)
                continue
            if header == 'SHT_PROGBITS':
                self.parse_progbits()
                continue
            
            receptor.emit_bytes(section.data())
