import os
import sys
sys.path.append("..")
import disassembler

def setup():
    pass

def test():
    #disassembler.parse_file
    disasembler2 = disassembler.Disassembler("../thirdparty/elf-32-high-bss")
    testabs32(disasembler2)
    d = disassembler.Disassembler("file1")
    # disassembler.rel32s
    # disassembler.abs32s
    # TODO なにがrel32なの？
    # main
    #     115d:       e8 d7 ff ff ff          call   1139 <subroutine>
    #

    testrel32(d)

def testabs32(d):
    if len(d.receptor.abs32s) != 4:
        print("Error abs32")

"""
Test rel32
"""
def testrel32(d):
    if "1139" in d.receptor.rel32s:
        return -1
    pass

if __name__ == "__main__":
    setup()
    test()
