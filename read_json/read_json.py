import argparse
import json


parser = argparse.ArgumentParser(description='Read JSON and dump to DB')
parser.add_argument('-f', nargs=1, required=True, help='Input JSON File')

args = parser.parse_args()

f = open(args.f[0], "r")
j = json.load(f)

for key in j:
    print key, " ", j[key]
