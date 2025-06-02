import os

outfile = "doits.txt"
with open("doit_instructions.txt", "r") as f:
    lines = [l.split()[0].lower() + "\n" for l in f.readlines() if not l.startswith("#")]
    out = []
    i = 0
    while i < len(lines):
        curr = lines[i]
        out += curr
        while i < len(lines) and lines[i] == curr:
            i += 1

with open(outfile, "w") as o:
    o.writelines(out)