import argparse
import disassembler

parser = argparse.ArgumentParser('Updater')
parser.add_argument('old_file', type=str)
parser.add_argument('new_file', type=str)

args = parser.parse_args()

print(args.old_file)
print(args.new_file)
x = disassembler.Disassembler(args.old_file)
y = disassembler.Disassembler(args.new_file)
