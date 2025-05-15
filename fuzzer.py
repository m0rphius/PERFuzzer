from argparse import ArgumentParser, ArgumentTypeError

from matplotlib.pylab import rand
import test
from generator import InstructionSet, generate_test_case, register_allowlist, memory_register_list
import os
import random
import mmap
import subprocess
import tempfile
import ctypes

def run():
    # ===================================================================================
    # Parse arguments
    parser = ArgumentParser(add_help=True)
    parser.add_argument("-n",
        "--num-test-cases",
        type=int,
        default=10,
        help="Number of test cases to generate.",)
    
    parser.add_argument("-p",
        "--program-size",
        type=int,
        default=30,
        help="Number of instructions per test case (can be larger due to alignment of mem-accesses).",)
    
    parser.add_argument("-core",
        "--core-id",
        type=int,
        default=2,
        help="Logical ID of the core that will run the tests.",)

    parser.add_argument("-m",
        "--mem-accesses",
        type=int,
        default = 10,
        help="Number of mem accesses per test case (if > program_size/2 than automatically set to program_size/2).",)

    parser.add_argument("-s",
        "--seed",
        type=int,
        default = 123456789,
        help="Seed for the inputs and test case generation.",)

    parser.add_argument("-conf",
        "--config-file",
        type=str,
        default = "/home/doit_prj/proj/nanoBench/fuzzing/configs/cfg_AlderLakeP_common.txt",
        help="Seed for the inputs and test case generation.",)

    parser.add_argument("-i",
        "--instruction-spec",
        type=str,
        default="/home/doit_prj/proj/nanoBench/fuzzing/utils/base.json",
        help="A JSON file which contains all the available instructions for this u-arch (see base.json).",)
    
    parser.add_argument("-f",
        "--instruction-filter",
        type=str,
        default="/home/doit_prj/proj/nanoBench/fuzzing/utils/doits.txt",
        help="A text file which contains a list of allowed instructions (optional).",)

    parser.add_argument("-o",
        "--out-directory",
        type=str,
        default="/home/doit_prj/proj/nanoBench/fuzzing/tmp",
        help="The directory in which tests will be created.",)
    parser.add_argument("-D",
        "--debug",
        action="store_true",
        help="Debug mode.",)
    
    args = parser.parse_args()
    # ===================================================================================

    # Initialize instruction set from the data base and filter
    filter = None
    with open(args.instruction_filter, "r") as f:
        filter = f.readlines()
        filter = [l[:-1] for l in filter] # Remove the unnecessary newline
    instruction_spec = InstructionSet(args.instruction_spec, filter)
    # ===================================================================================
    # Initialize test params
    debug = args.debug
    num_test_cases = args.num_test_cases
    program_size = args.program_size
    core_id = args.core_id
    config = args.config_file
    mem_accesses = args.mem_accesses
    chosen_seed = args.seed
    random.seed(chosen_seed)
    if mem_accesses > (program_size / 2):
        mem_accesses = (program_size / 2)
    outdir = args.out_directory
    if not os.path.exists(outdir):
        print("ERROR: {s} doesn't exist!".format(s=outdir))
        exit(1)
    elif not os.path.isdir(outdir):
        print("ERROR: {s} isn't a directory!".format(s=outdir))
        exit(1)
    # ===================================================================================
    
    print("\n" + "=" * 70)
    print("Params for fuzzer:\n")
    print(f"num_test_cases={num_test_cases}\nprogram_size={program_size}\nmem_accesses={mem_accesses}\noutdir={outdir}\ncore_id={core_id}\nconfig={config}\ninstruction_filter={args.instruction_filter}\ninstruction_spec={args.instruction_spec} ({len(instruction_spec.instructions)} instructions after filtering)\n")
    print(f"seed={chosen_seed}")
    print("=" * 70 + "\n")
    print(f"Running {num_test_cases} test cases...\n")

    # ===================================================================================
    # Start fuzzing!
    for i in range(num_test_cases):
        print(f"[{i+1}/{num_test_cases}] Running test case #{i+1}", end="\n")

        # Generate random test code
        test_code = '"' + generate_test_case(program_size, mem_accesses, instruction_spec) + '"'

        # # If Debug: save testcase
        # if debug:
        #     with open(f"tmp/test{i+1}.asm", "w") as f:
        #         f.write(test_code[1:-1])

        # Try inputs
        num_inputs = 25
        for j in range(3):
            # Run nanoBench on test case with increasing number of inputs
            print(f"Running with {num_inputs} inputs...")
            outfile = f"{outdir}/test{i+1}_{num_inputs}inputs.res"
            # print(f"sudo taskset -c {core_id} ./nanoBench.sh -f -unroll 100 -config {config} -num_inputs {num_inputs} -seed {chosen_seed} -asm {test_code} > {outfile}")
            try:
                os.system(f"sudo taskset -c {core_id} ../nanoBench.sh -f -basic_mode -config {config} -num_inputs {num_inputs} -seed {chosen_seed} -asm {test_code} > {outfile}")
            except:
                print(f"[ERROR] in test case {i}")
                exit(1)
            num_inputs *= 2

    # ===================================================================================
    # Done fuzzing
    print("\n" + "=" * 70)
    print("DONE FUZZING!\n")
        
if __name__ == "__main__":
    run()