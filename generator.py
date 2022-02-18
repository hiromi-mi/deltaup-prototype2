from io import StringIO
import bsdiff4
from disassembler import Receptor

def generate(f : StringIO, receptor_old : Receptor, receptor_new : Receptor):
    f.write(bsdiff4.diff(receptor_old.abs32s, receptor_new.abs32s))
    f.write(bsdiff4.diff(receptor_new.rel32s, receptor_new.rel32s))
    f.write(bsdiff4.diff(receptor_new.emitted_bytes, receptor_new.emitted_bytes))
    f.close()

def apply(f: StringIO, receptor_old: Receptor, receptor_new: Receptor):
    l = 30
    receptor_new.abs32s = bsdiff4.patch(receptor_old.abs32s, f.read(l))
    receptor_new.rel32s = bsdiff4.patch(receptor_old.rel32s, f.read(l))
    receptor_new.emitted_bytes = bsdiff4.patch(receptor_old.emitted_bytes, f.read(l))