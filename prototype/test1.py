# /tmp/1 バイナリの main 関数部分を逆アセンブルして call, jmp の address をとりだす
# SPDX-FileCopyrightText: 2020 hiromi_mi
# SPDX-License-Identifier: CC0-1.0
#
##include <stdio.h>
#int func(int x) {
#   return 11 + x;
#}
# int main() {
#   printf("Hello");
#   return func(3);
#}

from elftools.elf.elffile import ELFFile
import elftools.elf.sections as sections
from capstone import *

f = open("/tmp/1", "rb")
elffile = ELFFile(f)
symtable = elffile.get_section_by_name('.symtab')

# main 関数を取り出してみる
symmain = symtable.get_symbol_by_name('main')[0]
f.seek(symmain['st_value'])
maincode = f.read(symmain['st_size']) # main の生バイナリ
# b'UH\x89\xe5H\x8d=\xb1\x0e\x00\x00\xb8\x00\x00\x00\x00\xe8\xd3\xfe\xff\xff\xbf\x03\x00\x00\x00\xe8\xd2\xff\xff\xff]\xc3'

md = Cs(CS_ARCH_X86, CS_MODE_64)
# modr/m の部分など個別に取り出せるようにする
md.detail = True
# 0 は offset

# call, jmp 命令のあるアドレスだけ取り出す
instrs = list(filter(lambda x: x.mnemonic in ["call", "jmp"], md.disasm(maincode, 0)))
#for i in md.disasm(maincode, 0):
#    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

for instr in instrs:
    print(instr.mnemonic, end=' ')
    print(instr.op_str) # call のアドレス文字列が出力される

# 出力:
# call 0xfffffffffffffee8
# call 0xfffffffffffffff1

f.close()

