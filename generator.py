from io import StringIO
import bsdiff4
from disassembler import Receptor

def generate(f : StringIO, receptor_old : Receptor, receptor_new : Receptor):
    f.write(bsdiff4.diff(receptor_old.abs32, receptor_new.abs32))
    f.write(bsdiff4.diff(receptor_new.rel32, receptor_new.rel32))
    f.write(bsdiff4.diff(receptor_new.emitted_bytes, receptor_new.emitted_bytes))
    f.close()