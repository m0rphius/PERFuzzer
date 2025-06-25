import subprocess
import numpy as np
from typing import List
import struct

from fuzzer import VarInput

NUM_CHANGING_REGS = 4 # (rax, rbx, rcx, rdx)
NUM_CONSTANT_REGS = 6 # (r8, r9, r10, r11, r12, r13)


def flatten(lst):
    return [x for xs in lst for x in xs]

def write_inputs(constant_inputs : List[int], variable_inputs : List[VarInput]):
    # print(constant_inputs + inputs)
    
    variable_inputs_raw = [input.values for input in variable_inputs]
    variable_inputs_raw = flatten(variable_inputs_raw)

    all_inputs = constant_inputs + variable_inputs_raw
    with open("/sys/FuzzerBench/inputs", "wb") as f:
        for inp in all_inputs:
            f.write(int(inp).to_bytes(length=4, byteorder='little'))
        

def initialize_experiment(testcase : str = None, num_inputs : int = None, config : str = None, seed : int = None, cpu : int = None,
                          num_measurements : int = None, warmup_count : int = None, aggregate_func : str = None):
    params = " -df " 
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