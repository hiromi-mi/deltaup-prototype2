import argparse
import disassembler
import adjustment

parser = argparse.ArgumentParser('Updater')
parser.add_argument('old_file', type=str)
parser.add_argument('new_file', type=str)

args = parser.parse_args()

x = disassembler.Disassembler(args.old_file)
y = disassembler.Disassembler(args.new_file)
x.disassemble()
y.disassemble()

problem = adjustment.Problem()
problem.output()
