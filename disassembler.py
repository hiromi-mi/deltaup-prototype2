from elftools.elf.elffile import ELFFile
import elftools.elf.sections as sections
from capstone import *

class Disassembler:
    def __init__(self, fname):
        self.fname = fname

    def disassemble(self):
        f = open(self.fname, "rb")
        elffile = ELFFile(f)
        symtable = elffile.get_section_by_name('.symtab')

        instrs_all = []
        for sym in symtable.get_symbols():
            f.seek(sym['st_value'])
            code = f.read(sym['st_size'])

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            # modr/m の部分など個別に取り出せるようにする
            md.detail = True
            instrs = list(filter(lambda x: x.mnemonic in ["call", "jmp"], md.disasm(maincode, 0)))
            #for i in md.disasm(maincode, 0):
            #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

            instrs_all.append(instrs)

        return instrs_all
