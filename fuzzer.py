from argparse import ArgumentParser, ArgumentTypeError
from generator import InstructionSet, generate_test_cases
import os
import random

def run():
    # ===================================================================================
    # Parse arguments
    parser = ArgumentParser(add_help=True)
    parser.add_argument("-n",
        "--num-test-cases",
        type=int,
        default=100,
        help="Number of test cases to generate.",)
    
    parser.add_argument("-p",
        "--program-size",
        type=int,
        default=50,
        help="Number of instructions per test case (can be larger due to alignment of mem-accesses).",)
    
    parser.add_argument("-cpu",
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
        default = 29348471,
        help="Seed for the inputs and test case generation.",)

    parser.add_argument("-conf",
        "--config-file",
        type=str,
        default = "configs/cfg_AlderLakeP_all.txt",
        help="Seed for the inputs and test case generation.",)

    parser.add_argument("-i",
        "--instruction-spec",
        type=str,
        default="fuzzing/utils/base.json",
        help="A JSON file which contains all the available instructions for this u-arch (see base.json).",)
    
    parser.add_argument("-f",
        "--instruction-filter",
        type=str,
        default="fuzzing/utils/doits.txt",
        help="A text file which contains a list of allowed instructions (optional).",)

    parser.add_argument("-o",
        "--out-directory",
        type=str,
        default="fuzzing/tmp",
        help="The directory in which tests will be created.",)
    
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
    # Generate test cases
    generate_test_cases(num_test_cases, program_size, mem_accesses, outdir, instruction_spec, chosen_seed)
    # Run test cases
    print("\n" + "=" * 70)
    print(f"Running {num_test_cases}\n test cases...")
    
    for i in range(num_test_cases):
        print(f"[{i+1}/{num_test_cases}] Running test case #{i}", end="\n")
        bin_filename = f"{outdir}/test{i+1}/test{i+1}.bin"
        try:
            os.system(f"mkdir {outdir}/test{i+1}/results")
        except:
            print("[ERROR]", "Couldn't open result dir for {bin_file}!".format(bin_file=bin_filename))
            exit(1)
        for j in range(50):
            res_filename = f"{outdir}/test{i+1}/results/run{j+1}.res"
            asm_init_code = "mov rax, {val1}\nmov rbx, {val2}\nmov rcx, {val3}\nmov rdx, {val4}\nmov rdi, {val5}\nmov rsi, {val6}\n" \
            "mov r8, {val7}\nmov r9, {val8}\nmov r10, {val9}\nmov r11, {val10}\nmov r12, {val11}\nmov r13, {val12}\n".format(
                val1=random.randint(0, pow(2, 32) - 1),
                val2=random.randint(0, pow(2, 32) - 1),
                val3=1,
                val4=random.randint(0, pow(2, 32) - 1),
                val5=random.randint(0, pow(2, 32) - 1),
                val6=random.randint(0, pow(2, 32) - 1),
                val7=random.randint(0, pow(2, 12) - 1),
                val8=random.randint(0, pow(2, 12) - 1),
                val9=random.randint(0, pow(2, 12) - 1),
                val10=random.randint(0, pow(2, 12) - 1),
                val11=random.randint(0, pow(2, 12) - 1),
                val12=random.randint(0, pow(2, 12) - 1),
            )
            #print(asm_init_code)


            try:
                os.system("sudo taskset -c {core_id} ./nanoBench.sh -f -unroll 100 -config {conf_file} -code {bin_file} -asm_init "'"{init_code}"'" > {res_file}".format(
                    core_id=core_id,
                    bin_file=bin_filename,
                    init_code=asm_init_code,
                    res_file=res_filename,
                    conf_file=config,
                ))
            except:
                print("[ERROR]", "Couldn't run {bin_file}!".format(bin_file=bin_filename))
                exit(1)
        

if __name__ == "__main__":
    run()