import os
import sys
sys.path.append("..")
import disassembler
import adjustment

def setup():
    pass

def test():
    #disassembler.parse_file
    disasembler2 = disassembler.Disassembler("../thirdparty/elf-32-high-bss")
    testabs32(disasembler2, 0)
    d = disassembler.Disassembler("file1")
    testabs32(d, 3)
    # disassembler.rel32s
    # disassembler.abs32s
    # TODO なにがrel32なの？
    # main
    #     115d:       e8 d7 ff ff ff          call   1139 <subroutine>
    #

    testrel32(d)

def testadjustment():
    problem = adjustment.Problem("../thirdparty/elf-32-1","../thirdparty/elf-32-2")

    pass

def testabs32(d, cnt):
    if len(d.receptor.abs32s) != cnt:
        print(f"Error abs32 {d.receptor.abs32s}")
    else:
        print(f"abs32 OK {d.receptor.abs32s}")

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
