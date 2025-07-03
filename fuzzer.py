"""
CPU Fuzzer - A tool for generating and executing CPU test cases
"""

import os
import random
import datetime
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Tuple, Optional
from dataclasses import dataclass, field
import re

from tqdm import tqdm, TqdmWarning
import warnings
warnings.filterwarnings("ignore", category=TqdmWarning, module="tqdm")

from generator import InstructionSet, generate_test_case

KM_MEM_SIZE = 8192

@dataclass
class FuzzerConfig:
    """Configuration parameters for the fuzzer"""
    template: Optional[str] = None
    num_fuzzing_rounds: int = 10
    inputs : Optional[List[str]] = field(default_factory=list)
    memory_static : bool = False
    memory_binary : Optional[str] = None
    program_size: int = 30
    core_id: int = 2
    mem_accesses: int = 10
    n_reps : int = 50
    n_inputs : int = 5
    scale_factor : float = 1.1
    difference_threshold : float = 0.5
    frequency_threshold : float = 0.5
    stat_threshold : float = 0.5
    outliers_threshold : float = 0.2
    seed: int = 123456789
    warmup_count: int = 1
    aggregate_func: Optional[str] = "avg"
    analyzer_type: Optional[str] = "chi"
    config_file: Optional[str] = None
    counter_ids : List[int] = field(default_factory=list)
    n_counters : int = 0
    instruction_spec: str = ""
    instruction_filter: str = ""
    instruction_count : int = 0     # Internal
    out_directory: str = ""
    debug: bool = False
    plot: bool = False
    verbose : bool = False
    color : bool = False

    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.template:
            if not os.path.exists(self.template) or not os.path.isfile(self.template):
                raise ValueError(f"{self.template} is not a legal source name")

        if not self.template and self.mem_accesses > (self.program_size // 2):
            self.mem_accesses = self.program_size // 2
            
        if self.aggregate_func not in ["avg", "min", "max", "median"]:
            raise ValueError(f"{self.aggregate_func} is not a valid aggregation function")
            
        if not self.config_file:
            self.config_file = self._get_default_config()

        if self.inputs:
            for input in self.inputs:
                if not os.path.exists(input) or not os.path.isfile(input):
                    raise ValueError(f"{input} is not a legal input file name")
            if len(self.inputs) < self.warmup_count + 1:
                raise ValueError(f"Not enough inputs were provided (< warmup_count + 1)")

        if self.memory_binary:
            if not os.path.exists(self.memory_binary) or not os.path.isfile(self.memory_binary):
                    raise ValueError(f"{self.memory_binary} is not a legal binary")

        with open(self.config_file, "r") as f:
            # print(f.readlines())
            cnames = [l.split()[1] for l in f.readlines() if l != "\n" and not l.startswith("#")]
            assert len([c for c in cnames if (type(c) != str or c == "")]) == 0, "Parsed an illegal counter config (name issue)!"
            self.counter_ids = cnames
            self.n_counters = len(cnames)

    
    def _get_default_config(self) -> str:
        """Get default config based on core_id"""
        if self.core_id in range(0, 16):
            return "configs/cfg_AlderLakeP_common.txt"
        return "configs/cfg_AlderLakeE_common.txt"

class FuzzerError(Exception):
    """Custom exception for fuzzer errors"""
    pass


class OutputManager:
    """Handles output"""
    
    def __init__(self, base_path: str = None):
        if base_path:
            self.base_path = Path(base_path)
            self.path = self._create_directory()
        
    def _create_directory(self) -> Path:
        """Create timestamped output directory"""
        if not self.base_path.exists():
            raise FuzzerError(f"{self.base_path} doesn't exist!")
        
        if not self.base_path.is_dir():
            raise FuzzerError(f"{self.base_path} isn't a directory!")
        
        timestamp = datetime.datetime.now().strftime('%Y-%d-%m-%H%M')
        fuzz_id = f"fuzz{timestamp}"
        outdir = self.base_path / fuzz_id
        
        try:
            outdir.mkdir(exist_ok=True)
        except OSError as e:
            raise FuzzerError(f"Couldn't create output directory: {e}")
        
        return outdir
    
    def save_params(self, config: FuzzerConfig):
        """Save fuzzer parameters to file"""
        params = self._format_params(config)
        params_file = self.path / "fuzz.params"
        params_file.write_text(params)
    
    def save_test_case(self, test_number: int, test_code: str):
        """Save test case assembly code"""
        test_file = self.path / f"test{test_number}.asm"
        test_file.write_text(test_code)
    
    def save_results(self, test_number: int, n_reps: int, output: str):
        """Save test results"""
        result_file = self.path / f"test{test_number}_{n_reps}nreps.res"
        result_file.write_text(output)
    
    def save_results_colored(self, test_number: int, n_reps: int, output: str, colors):
        lines = output.splitlines()
        html_lines = []

        for i, line in enumerate(lines):
            color = colors[i % len(colors)]
            html_lines.append(f'<div style="color:{color}; margin:0">{line}</div>')

        full_html = "<html><body style='font-family:monospace;'>\n" + "\n".join(html_lines) + "\n</body></html>"
        
        filename = self.path / f"test{test_number}_{n_reps}nreps_colored.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(full_html)

    
    def _format_params(self, config: FuzzerConfig) -> str:
        """Format parameters for printing and saving"""
        if config.analyzer_type == "threshold":
            analyzer_str = f"threshold [dt={config.difference_threshold} df={config.frequency_threshold}]"
        elif config.analyzer_type == "chi":
            analyzer_str = f"chi [st={config.stat_threshold} ot={config.outliers_threshold}]"

        if config.template:
            template = """
    Template Fuzzing

    Template      : {template_asm}
    Scale Factor    : {scale_factor}
    Analyzer        : {analyzer_str}
    Seed            : {seed}
    Warmup Count    : {warmup_count}
    Memory Static   : {memory_static}
    Memory Binary   : {memory_binary}
    Config File     : {config_file}
    Core ID         : {core_id}{output_dir}
            """.format(template_asm=config.template,
            scale_factor=config.scale_factor,
            analyzer_str=analyzer_str,
            seed=config.seed,
            warmup_count=config.warmup_count,
            memory_static=config.memory_static,
            memory_binary=config.memory_binary,
            config_file=config.config_file,
            core_id=config.core_id,
            output_dir=f"\nOutput Dir      : {self.path}" if config.debug else "")
        else:
            template = """
Regular Fuzzing:

Test Cases      : {num_test_cases}
Instructions    : {instruction_count} loaded from {instruction_spec}
Filter          : {instruction_filter}
Program Size    : {program_size}
Memory Accesses : {mem_accesses}
Memory Static   : {memory_static}
Memory Binary   : {memory_binary}
Scale Factor    : {scale_factor}
Analyzer        : {analyzer_str}
Seed            : {seed}
Warmup Count    : {warmup_count}
Config File     : {config_file}
Core ID         : {core_id}{output_dir}
            """.format(num_test_cases=config.num_fuzzing_rounds,
            instruction_count=config.instruction_count,
            instruction_spec=config.instruction_spec,
            instruction_filter=config.instruction_filter,
            program_size=config.program_size,
            mem_accesses=config.mem_accesses,
            memory_static=config.memory_static,
            memory_binary=config.memory_binary,
            scale_factor=config.scale_factor,
            analyzer_str=analyzer_str,
            seed=config.seed,
            warmup_count=config.warmup_count,
            config_file=config.config_file,
            core_id=config.core_id,
            output_dir=f"\nOutput Dir      : {self.path}" if config.debug else "")
        
        return template

@dataclass
class Input:
    id : int
    values : List[int]

    def __str__(self):
        reg_names = {'eax' : 0, 'ebx' : 0, 'ecx' : 0, 'edx' : 0, 'r8' : 0, 'r9' : 0, 'r10' : 0, 'r11' : 0, 
                    'r12' : 0, 'r13' : 0}
        return f"Input {self.id}: [{', '.join([f"{reg}={hex(v)}" for reg, v in zip(reg_names.keys(), self.values)])}]"

class TestCaseRunner:
    """ Handles execution of individual test cases """
    
    def __init__(self, config: FuzzerConfig, output_manager: OutputManager):
        self.config = config
        self.output_manager = output_manager
        self.n_reps = config.n_reps
        if config.inputs:
            self.n_inputs = len(config.inputs)
        else:
            self.n_inputs = config.n_inputs
        self.memory_binary = None
        if config.memory_binary:
            with open(config.memory_binary, "rb") as f:
                self.memory_binary = list(f.read(KM_MEM_SIZE))
    
    def run_test_case(self, test_number: int, test_code: str) -> str:
        """ Run a single test case and return results """

        from utils import (
            write_inputs, 
            initialize_experiment,
            NUM_VAR_REGS
        )

        formatted_code = f'"{test_code}"'
        # formatted_code = f'"or rcx, 1\nand rdx, rcx\nshr rdx, 1\ndiv rcx"'

        if self.config.debug:
            self.output_manager.save_test_case(test_number, test_code)
        
        # Initialize experiment
        self.__init_mem()
        initialize_experiment(testcase=formatted_code)

        # Generate inputs
        if self.config.inputs:
            inputs = self.__load_inputs()
        else:
            inputs = self.__generate_inputs()

        write_inputs(inputs)
        
        # Configure experiment
        initialize_experiment(
            config=self.config.config_file,
            num_inputs=self.n_inputs,
            seed=self.config.seed,
            cpu=self.config.core_id,
            aggregate_func=self.config.aggregate_func,
            warmup_count=self.config.warmup_count
        )
        
        # Run experiment with progress tracking
        output = self._run_experiment_with_progress(test_number)
        
        if self.config.debug:
            # if self.config.color:
            #     self.output_manager.save_results_colored(test_number, self.n_reps, output,
            self.output_manager.save_results(test_number, self.n_reps, output)
        
        
        return output, inputs
    
    def _run_experiment_with_progress(self, test_number: int) -> str:
        """ Run experiment with progress bar """
        desc = (f"[test {test_number}/{self.config.num_fuzzing_rounds}, "
                f"nr={self.n_reps}, ni={self.n_inputs}, "
                f"p={self.config.program_size}, m={self.config.mem_accesses}]")
        
        output = ""
        
        with open("/sys/FuzzerBench/trace", 'rb') as trace:
            print(f"Running {desc}")
            for rep in range(self.n_reps):
                try:
                    output += trace.read().decode('utf-8')
                    trace.seek(0)
                except Exception as e:
                    raise FuzzerError(f"Error reading measurements: {e}")
                    
        
        return output
    
    def _scale_parameters(self):
        """ Scale parameters for next iteration """
        scale = self.config.scale_factor
        self.n_reps = round(self.n_reps * scale)
        self.n_inputs = round(self.n_inputs * scale)
        self.config.program_size = round(self.config.program_size * scale)
        self.config.mem_accesses = round(self.config.mem_accesses * scale)

    def __generate_inputs(self) -> List[Input]:
        """ Generate constant and variable inputs for the test """
        scales = [(2**i) - 1 for i in range(31)]
        
        from utils import(
            NUM_VAR_REGS,
            NUM_MEM_REGS
        )   
        
        if self.config.memory_static:
            # Assign the same memory reg values for each input group
            mem_regs_values = [random.randint(0, (2**13) - 1) for _ in range(NUM_MEM_REGS)]
        
        _inputs = []
        for i in range(self.config.warmup_count + self.n_inputs):
            a = random.choice(scales)
            b = random.choice(scales)
            var_regs_values=[random.randint(min(a,b), max(a,b)) for _ in range(NUM_VAR_REGS)]
            if not self.config.memory_static:
                mem_regs_values = [random.randint(0, (2**13) - 1) for _ in range(NUM_MEM_REGS)]
            # print(mem_regs_values)
            _inputs.append(Input(id=i-self.config.warmup_count, values=var_regs_values + mem_regs_values))

        inputs = _inputs * self.n_reps
        
        return inputs
    
    def __load_inputs(self) -> List[Input]:
        """ Load inputs from the inputs files in the fuzzer configuration """
        from utils import NUM_VAR_REGS

        _inputs = []

        pattern = r'^(eax|ebx|ecx|edx|r8|r9|r10|r11|r12|r13)=([-+]?(0x[0-9a-fA-F]+|0b[01]+|\d+))$'

        for i, input_file in enumerate(self.config.inputs):
            with open(input_file, "r") as f:
                # Verify pattern
                lines = [l for l in f.readlines() if re.fullmatch(pattern, l[:-1])]

                # Verify that all regs are provided
                reg_values = {'eax' : 0, 'ebx' : 0, 'ecx' : 0, 'edx' : 0, 'r8' : 0, 'r9' : 0, 'r10' : 0, 'r11' : 0, 
                              'r12' : 0, 'r13' : 0}
                for l in lines:
                    if l.startswith('r9') or l.startswith('r8'):
                        reg = l[0:2]
                        value = l[3:-1]
                    else:
                        reg = l[0:3]
                        value = l[4:-1]
                    reg_values[reg] = int(value, base=0)
                
                # print([hex(v) for v in reg_values.values()])
                _inputs.append(Input(id=i-self.config.warmup_count, values=reg_values.values()))

        inputs = _inputs * self.n_reps
        return inputs
    
    def __init_mem(self):
        """ Init the tester's memory """
        from utils import write_mem
        memory_binary = self.memory_binary
        if not memory_binary:
            memory_binary = [random.randint(0, (2**8) - 1) for _ in range(KM_MEM_SIZE)]
            self.memory_binary = memory_binary
        write_mem(memory_binary)


class CPUFuzzer:
    """Main fuzzer class that orchestrates the fuzzing process"""
    
    def __init__(self, config: FuzzerConfig):
        from analyzer import ThresholdAnalyzer, ChiAnalyzer
        self.config = config
        self.output_manager = OutputManager(config.out_directory) if config.debug else OutputManager()
        self.config.out_directory = self.output_manager.path
        self.instruction_set = self._load_instruction_set()
        self.config.instruction_count = len(self.instruction_set.instructions)
        self.test_runner = TestCaseRunner(config, self.output_manager)
        if self.config.analyzer_type == "threshold":
            self.analyzer = ThresholdAnalyzer(difference_threshold=config.difference_threshold,
                                 frequency_threshold=config.frequency_threshold)
        elif self.config.analyzer_type == "chi":
            print("HERE")
            self.analyzer = ChiAnalyzer(self.config.stat_threshold, self.config.outliers_threshold)
        # Set random seed
        random.seed(config.seed)
    
    def _load_instruction_set(self) -> InstructionSet:
        """Load and filter instruction set"""
        filter_instructions = None
        
        if self.config.instruction_filter:
            with open(self.config.instruction_filter, "r") as f:
                filter_instructions = [line.strip() for line in f.readlines()]
        
        return InstructionSet(self.config.instruction_spec, filter_instructions)

    def run(self):
        """"
        Entry point when starting the fuzzer 
        
        if provided template => template fuzz
        else => regular fuzz

        """
        
        if self.config.template:
            try: 
                with open(self.config.template, "r") as f:
                    test_code = f.read()
            except:
                print(f"[ERROR] fuzzer: error while reading / opening template file")

            self.__template_fuzz(test_code) 
        else:
            self.__fuzz()

    def __fuzz(self):
        """Regular fuzz - works on randomly generated test cases"""
        from analyzer import AnalyzerError
        sep = "="*140
        
        print(self.output_manager._format_params(self.config))
        print(sep)

        if self.config.debug:
            self.output_manager.save_params(self.config)
        
        print("Start fuzzing...")
        
        for i in range(self.config.num_fuzzing_rounds):
            test_code = generate_test_case(
                self.config.program_size,
                self.config.mem_accesses,
                self.instruction_set
            )
            
            try:
                output, inputs = self.test_runner.run_test_case(i + 1, test_code)

                # Violation analysis
                violations = self.analyzer.analyze(output, 
                                                   test_code,
                                                   i+1,
                                                   inputs, 
                                                   self.config, 
                                                   self.test_runner.n_reps, 
                                                   self.test_runner.n_inputs,
                                                   self.test_runner.memory_binary)
                if violations > 0:
                    break
                # Scale parameters for next iteration
                if not self.config.inputs:
                    self.test_runner._scale_parameters()
            except FuzzerError as e:
                print(f"[ERROR] fuzzer: {e}")
                return
            except AnalyzerError as e:
                print(f"[ERROR] analyzer: {e}")
                return

        """Print completion message"""
        print(sep + "\nDONE FUZZING!\n")
        if self.config.debug:
            print(f"Inspect results in {self.output_manager.path}")

    def __template_fuzz(self, test_code : str):
        """Template fuzz - works on a predefined test case"""

        from analyzer import AnalyzerError
        sep = "="*140
        
        print(self.output_manager._format_params(self.config))
        print(sep)

        if self.config.debug:
            self.output_manager.save_params(self.config)
        
        print("Start fuzzing...")
        
        for i in range(self.config.num_fuzzing_rounds):
            
            try:
                output, inputs = self.test_runner.run_test_case(i + 1, test_code)

                # Violation analysis
                violations = self.analyzer.analyze(output, 
                                                   test_code,
                                                   i+1,
                                                   inputs, 
                                                   self.config, 
                                                   self.test_runner.n_reps, 
                                                   self.test_runner.n_inputs,
                                                   self.test_runner.memory_binary)
                if violations > 0:
                    break
                # Scale parameters for next iteration
                if not self.config.inputs:
                    self.test_runner._scale_parameters()
            except FuzzerError as e:
                print(f"[ERROR] fuzzer: {e}")
                return
            except AnalyzerError as e:
                print(f"[ERROR] analyzer: {e}")
                return


def create_argument_parser() -> ArgumentParser:
    """Create and configure argument parser"""
    cwd = os.getcwd()
    parser = ArgumentParser()
    
    parser.add_argument("-t", "--template", type=str,
                       help="Provide an asm template to the fuzzer in INTEL syntax" \
                       " (if provided all regular fuzzing parameters are ignored)")
    parser.add_argument("-n", "--num-fuzzing-rounds", type=int, default=10,
                       help="Number of fuzzing rounds")
    parser.add_argument("-nr", "--num-repetitions", type=int, default=50,
                       help="Number of repetitions of the 1st testcase")
    parser.add_argument("-ni", "--num-inputs", type=int, default=5,
                       help="Number oif inputs to the 1st testcase")
    parser.add_argument("-I", "--inputs", nargs='+', type=str, 
                        help='List of inputs to the fuzzer. txt files where each line is in format "'"REG32=VAL"'"' \
                        'If provided then "'"--num-fuzzing-rounds"'" is ignored).')
    parser.add_argument("-ms", "--memory-static", action="store_true",
                       help="Keep memory accesses identical between inputs to the same testcase " \
                       "(intended for DOIT testcases).")
    parser.add_argument("-M", "--memory-binary", type=str,
                        help="A binary file that contains the memory content for the test (optional).")
    parser.add_argument("-p", "--program-size", type=int, default=30,
                       help="Number of instructions per test case")
    parser.add_argument("-core", "--core-id", type=int, default=2,
                       help="Logical ID of the core that will run the tests")
    parser.add_argument("-m", "--mem-accesses", type=int, default=10,
                       help="Number of memory accesses per test case")
    parser.add_argument("-S", "--scale-factor", type=float, default=1.1,
                       help="Scale of parameters growth between test cases.")
    parser.add_argument("-dt", "--diff-threshold", type=float, default=0.5,
                       help="Difference threshold for the threshold analyzer (ignored for other analyzer).")
    parser.add_argument("-ft", "--freq-threshold", type=float, default=0.5,
                       help="Frequency threshold for the threshold analyzer (ignored for other analyzer).")
    parser.add_argument("-st", "--stat-threshold", type=float, default=0.5,
                       help="Stats threshold for the Chi-Square analyzer (ignored for other analyzer).")
    parser.add_argument("-ot", "--outliers-threshold", type=float, default=0.2,
                       help="Outliers threshold for the Chi-Square analyzer (ignored for other analyzer).")
    parser.add_argument("-s", "--seed", type=int, default=123456789,
                       help="Seed for random generation")
    parser.add_argument("-w", "--warmup-count", type=int, default=1,
                       help="Number of warmup rounds before each experiment")
    parser.add_argument("-a", "--aggregate-func", type=str, default="avg",
                       choices=["avg", "min", "max", "median"],
                       help="Function used to aggregate measurements")
    parser.add_argument("-A", "--analyzer-type", type=str, default="chi",
                       choices=["chi", "threshold"])
    parser.add_argument("-conf", "--config-file", type=str,
                       help="Performance counters configuration file")
    parser.add_argument("-i", "--instruction-spec", type=str,
                       default=f"{cwd}/utils/base.json",
                       help="JSON file containing available instructions")
    parser.add_argument("-f", "--instruction-filter", type=str,
                       default=f"{cwd}/utils/doits.txt",
                       help="Text file with allowed instructions list")
    parser.add_argument("-o", "--out-directory", type=str,
                       default=f"{cwd}/results",
                       help="Directory for test output")
    parser.add_argument("-D", "--debug", action="store_true",
                       help="Enable debug mode")
    parser.add_argument("-P", "--plot", action="store_true",
                       help="Plot results")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Print diostribution of traces when reporting violations.")
    parser.add_argument("-C", "--color", action="store_true",
                       help="Colorize counter measurements line by line for better visibility.")

    return parser


def main():
    """Main entry point"""
    try:
        parser = create_argument_parser()
        args = parser.parse_args()
        
        # Create configuration from arguments
        config = FuzzerConfig(
            template=args.template,
            num_fuzzing_rounds=args.num_fuzzing_rounds,
            inputs=args.inputs,
            memory_static=args.memory_static,
            memory_binary=args.memory_binary,
            program_size=args.program_size,
            core_id=args.core_id,
            mem_accesses=args.mem_accesses,
            n_reps=args.num_repetitions,
            n_inputs=args.num_inputs,
            scale_factor=args.scale_factor,
            difference_threshold=args.diff_threshold,
            frequency_threshold=args.freq_threshold,
            stat_threshold=args.stat_threshold,
            outliers_threshold=args.outliers_threshold,
            seed=args.seed,
            warmup_count=args.warmup_count,
            aggregate_func=args.aggregate_func,
            analyzer_type=args.analyzer_type,
            config_file=args.config_file,
            instruction_spec=args.instruction_spec,
            instruction_filter=args.instruction_filter,
            out_directory=args.out_directory,
            debug=args.debug,
            plot=args.plot,
            verbose=args.verbose,
            color=args.color
        )
        
        # Run fuzzer
        fuzzer = CPUFuzzer(config)
        fuzzer.run()
        
    except (FuzzerError, ValueError) as e:
        print(f"[ERROR] fuzzer: {e}")
        exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Fuzzing interrupted by user")
        exit(0)


if __name__ == "__main__":
    main()