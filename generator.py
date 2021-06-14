import bsdiff4

def generate(f, receptor_old, receptor_new):
    f.write(bsdiff4.diff(receptor_old.abs32, receptor_new.abs32))
    f.write(bsdiff4.diff(receptor_new.rel32, receptor_new.rel32))
    f.write(bsdiff4.diff(receptor_new.emitted_bytes, receptor_new.emitted_bytes))
    f.close()
