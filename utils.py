from pathlib import Path
import subprocess
import numpy as np
from typing import List
import struct

from fuzzer import Input

NUM_VAR_REGS = 4 # (rax, rbx, rcx, rdx)
NUM_MEM_REGS = 6 # (r8, r9, r10, r11, r12, r13)


def flatten(lst):
    return [x for xs in lst for x in xs]

def write_inputs(inputs : List[Input]):
    inputs_raw = [inp.values for inp in inputs]
    inputs_raw = flatten(inputs_raw)

    with open("/sys/FuzzerBench/inputs", "wb") as f:
        for v in inputs_raw:
            f.write(int(v).to_bytes(length=4, byteorder='little'))

def write_mem(mem : List[int]):
    with open("/sys/FuzzerBench/mem", "wb") as f:
        for v in mem:
            f.write(int(v).to_bytes(length=1, byteorder='little'))

def makedirs(path : Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
    except:
        raise(ValueError(f"Couldn't open a directory at {path}"))

def initialize_experiment(testcase : str = None, num_inputs : int = None, config : str = None, seed : int = None, cpu : int = None,
                          num_measurements : int = None, warmup_count : int = None, aggregate_func : str = None):
    params = ""
    # If testcase is given, only write testcase and quit. 
    if testcase:
        params += f"-asm {testcase} "
    if num_inputs:
        params += f"-num_inputs {num_inputs} "
    if config:
        if "FuzzerBench/" in config:
            config = config.removeprefix("FuzzerBench/")
        params += f"-config {config} "
    if seed:
        params += f"-seed {seed} "
    if num_measurements:
        params += f"-n_measurements {num_measurements} "
    if warmup_count: 
        params += f"-warm_up_count {warmup_count} "
    if cpu: 
        params += f"-cpu {cpu} "
    if aggregate_func: 
        params += f"-{aggregate_func} "
    params += f" -unroll 1 "
    params += f" -basic_mode "
    subprocess.run(f"sudo FuzzerBench/init_params.sh {params}",shell=True, check=True)