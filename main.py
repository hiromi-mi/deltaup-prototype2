import argparse
import disassembler
import adjustment
import generator

parser = argparse.ArgumentParser('Updater')
parser.add_argument('old_file', type=str)
parser.add_argument('new_file', type=str)

args = parser.parse_args()

x = disassembler.Disassembler(args.old_file)
y = disassembler.Disassembler(args.new_file)
receptor_old = x.disassemble()
receptor_new = y.disassemble()

problem = adjustment.Problem(receptor_old, receptor_new)

with open("out.patch") as f:
    generator.generate(f, receptor_old, receptor_new)
