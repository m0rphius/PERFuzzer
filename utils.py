import subprocess
import numpy as np
from typing import List
import struct

NUM_CHANGING_REGS = 4 # (rax, rbx, rcx, rdx)
NUM_CONSTANT_REGS = 6 # (r8, r9, r10, r11, r12, r13)

def write_inputs(constant_inputs : List[int], inputs : List[int]):
    # print(constant_inputs + inputs)
    all_inputs = constant_inputs + inputs
    with open("/sys/nb/inputs", "wb") as f:
        for inp in all_inputs:
            f.write(int(inp).to_bytes(length=4, byteorder='little'))
        # f.write(struct.pack('>' + 'i' * len(constant_inputs), *constant_inputs))
        # f.write(struct.pack('>' + 'i' * len(inputs), *inuputs))

def initialize_experiment(testcase : str = None, num_inputs : int = None, config : str = None, seed : int = None, cpu : int = None,
                          num_measurements : int = None, warmup_count : int = None, aggregate_func : str = None):
    params = " -df " 
    # If testcase is given, only write testcase and quit. 
    if testcase:
        params += f"-asm {testcase} "
    if num_inputs:
        params += f"-num_inputs {num_inputs} "
    if config:
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
    subprocess.run(f"sudo ../initKernelNBParams.sh {params}",shell=True, check=True)