from argparse import ArgumentParser

from generator import InstructionSet, generate_test_case
from analyzer import analyze_results
import os
import random
import datetime
import numpy as np
import tqdm
from tqdm import tqdm

NUM_CHANGING_REGS = 4 # (rax, rbx, rcx, rdx)
NUM_CONSTANT_REGS = 6 # (r8, r9, r10, r11, r12, r13)

def _write_inputs(inputs : np.ndarray[np.int32]):
    
    # with open('/sys/nb/inputs', 'rb') as f:
    #     data = f.read()
    #     print(f"Raw bytes {data}")
    #     print(f"As hex: {data.hex()}")
    #     print(f"Length: {len(data)} bytes")

    #     n_reps = int(inputs.shape[0])
    #     n_inputs = int(inputs.shape[1])
    #     for i in range(n_reps):
    #         for j in range(n_inputs):
    #             print(f"Input {i, j}={data.hex()[i * (n_inputs * 8) + j * 8: i * (n_inputs * 8) + (j + 1) * 8]}")
    pass

def run():
    cwd = os.getcwd()
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
        default=None,
        help="Perfomance counters configuration file (format: '[EventSel].[UMask] [Name]').",)

    parser.add_argument("-i",
        "--instruction-spec",
        type=str,
        default=f"{cwd}/utils/base.json",
        help="A JSON file which contains all the available instructions for this u-arch (see base.json).",)
    
    parser.add_argument("-f",
        "--instruction-filter",
        type=str,
        default=f"{cwd}/utils/doits.txt",
        help="A text file which contains a list of allowed instructions (optional).",)

    parser.add_argument("-o",
        "--out-directory",
        type=str,
        default=f"{cwd}/results",
        help="The directory in which tests will be created.",)
    parser.add_argument("-D",
        "--debug",
        action="store_true",
        help="Debug mode.",)
    parser.add_argument("-P",
        "--plot",
        action="store_true",
        help="Plot results.",)
    
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
    if core_id in range(0,16) and not config:
        config = f"{cwd}/configs/cfg_AlderLakeP_common.txt"
    elif not config:
        config = f"{cwd}/configs/cfg_AlderLakeE_common.txt"
    mem_accesses = args.mem_accesses
    chosen_seed = args.seed
    random.seed(chosen_seed)
    np.random.seed(chosen_seed)
    if mem_accesses > (program_size / 2):
        mem_accesses = (program_size / 2)
    if not os.path.exists(args.out_directory):
        print(f"[ERROR] {args.out_directory} doesn't exist!")
        exit(1)
    elif not os.path.isdir(args.out_directory):
        print(f"[ERROR] {args.out_directory} isn't a directory!")
        exit(1)
    fuzz_id = f"fuzz{datetime.datetime.now().strftime('%Y-%d-%m-%H%M')}"
    outdir = f"{args.out_directory}/{fuzz_id}"
    try:
        os.system(f"mkdir {outdir}")
    except:
        print(f"[ERROR] in making an out directory")
        exit(1)
    plot = args.plot
    sample_sizes = [10, 25, 50, 100]

    # ===================================================================================
    # Print and store params
    print("\n" + "=" * 70)
    print("Params for fuzzer:\n")
    params = ""
    params += f"seed={chosen_seed}\n"
    params += f"num_test_cases={num_test_cases}\n"
    params += f"program_size={program_size}\n"
    params += f"mem_accesses={mem_accesses}\n"
    params += f"outdir={outdir}\n"
    params += f"core_id={core_id}\n"
    params += f"config={config}\n"
    params += f"instruction_filter={args.instruction_filter}\n"
    params += f"instruction_spec={args.instruction_spec} ({len(instruction_spec.instructions)} instructions after filtering)\n"
    print(params)
    print("=" * 70 + "\n")

    # For reproducibility 
    with open(f"{outdir}/fuzz.params", "w") as f:
        f.write(params)

    # ===================================================================================
    # Start fuzzing!
    print("Starting fuzzing...")
    num_inputs = 4
    with open('/sys/nb/inputs', 'wb') as file:
        for i in range(num_test_cases):
            # print(f"[{i+1}/{num_test_cases}] Running test case #{i+1}", end="\n")

            # Generate random test code
            test_code = '"' + generate_test_case(program_size, mem_accesses, instruction_spec) + '"'

            # # If Debug: save testcase
            if debug:
                with open(f"{outdir}/test{i+1}.asm", "w") as f:
                    f.write(test_code[1:-1])

            total = len(sample_sizes)
            tasks = [(f"[test {i+1}/{num_test_cases}, n_reps={n_reps}, n_inputs={num_inputs}]", 10 + 5 * min(j, total - j)) for (j, n_reps) in enumerate(sample_sizes)]

            progress = 0
            total_work = sum(weight for _, weight in tasks)
            pbar = tqdm(total=total_work, colour="green")

            # Try inputs
            for (j, (desc, weight)) in enumerate(tasks):
                pbar.set_description_str(desc)
                n_reps = sample_sizes[j]
                # Inputs that don't change between input groups
                constant_inputs = np.random.randint(low=0, high=(2**12) - 1, size=NUM_CONSTANT_REGS, dtype=np.int32)
                # Inputs that vary between input groups
                inputs = np.random.randint(low=0, high=(2**31), size=(n_reps, num_inputs * NUM_CHANGING_REGS), dtype=np.int32)
                # transfer to KM
                file.write(constant_inputs.tobytes())
                file.write(inputs.flatten().tobytes())

                outfile = f"{outdir}/test{i+1}_nreps{n_reps}.res"

                # Run nanoBench on test case with increasing number of inputs
                # print(f"sudo taskset -c {core_id} ./nanoBench.sh -config {config} -num_inputs {num_inputs} -seed {chosen_seed} -asm {test_code} > {outfile}")
                try:
                    os.system(f"sudo taskset -c {core_id} ../kernel-nanoBench.sh -config {config} -n_reps {n_reps} -num_inputs {num_inputs} -seed {chosen_seed} -asm {test_code} > {outfile}")
                except:
                    print(f"[ERROR] in test case {i}")
                    exit(1)
                progress += weight
                pbar.update(weight)
            # num_inputs *= 2

    pbar.close()

    # ===================================================================================
    # Analyze results
    # analyze_results(fuzz_dir=outdir, plot=plot, core_id=core_id)

    # ===================================================================================
    # Done fuzzing

    print("\n" + "=" * 70)
    print("DONE FUZZING!\n")
    print(f"Inspect results on {outdir}")
        
if __name__ == "__main__":
    run()