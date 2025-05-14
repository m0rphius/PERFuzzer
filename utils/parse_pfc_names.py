import os 
from typing import List

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

print("[", end="")
with open("../configs/cfg_AlderLakeE_all.txt", "r") as f:
    lines = f.readlines()
    i = 0
    for line in lines:
        if line != '' and is_hex(line[0][0]):
            i += 1
            pfc_name = line.split()[-1]
            print(f"'{pfc_name}'", end=",")
            if (i % 3 == 0):
                print("\n", end="")
print("]")