# PERFuzzer

**PERFuzzer** is a hardware-oriented instruction fuzzer designed to explore subtle behaviors in CPU microarchitecture using performance counters.  
Built on top of a custom kernel module called **FuzzBench** (a fork of nanoBench), it automates the generation, execution, and analysis of randomized instruction sequences to detect timing anomalies and microarchitectural side effects. The generation of random testcases and communication between the fuzzer and kernel module, is inspired by Microsoft's **Revizor**, which is also a fuzzer that searches for microarchitectural leaks in CPUs 

---

## Disclaimers
1. This tool executes arbitrary code in kernel space, use it with cuation.
   
2. Root access is required.

3. Before using the fuzzer you must know your architecture, since counter configurations are architecture-dependent.
If you have a hybrid architecture, then you must know the architecture for each core, and provide a compatible counter config (explained later).
The correctness and stability of the fuzzer isn't guaranteed when using wrong configurations. 

## Highlights

- Performance-counter-driven fuzzing
- Systematic exploration of instruction interactions
- Kernel module for accurate in-core measurements
- Input-controlled microbenchmarking (RAX, RBX, RCX, RDX)
- Scalable fuzzing with dynamic test generation and thresholds

---

## Structure

```text
  PERFuzzer/
  │
  ├── FuzzBench/ # Kernel module (submodule based on nanoBench)
  │ └── FuzzBench_km.c
  │
  ├── fuzzer.py # Main CLI for fuzzing
  ├── generator.py # Instruction generator from ISA spec
  ├── analyzer.py # Detects violations based on counter deviation
  ├── utils.py # Input encoding and test invocation
  │
  ├── configs/ # Counter and MSR configurations (txt)
  ├── utils/ # Instruction specs and filters
  │ ├── base.json 
  │
  └── results/ # (optional) Logs, ASM, measurements
```

## Installation 

### 1. Clone the repository
```bash
git clone --recurse-submodules https://github.com/your-username/PERFuzzer.git
cd PERFuzzer

# If you forgot "--recurse-submodules" run:
git submodule update --init --recursive
```
### 2. Build and insert the kernel module
```bash
cd FuzzBench
make
sudo insmod FuzzBench.ko
```

## Using the fuzzer

### Example 1: random fuzzing of 10 tests
The following command will fuzz 10 random generated tests, starting from 30 instruction, 10 memory accesses (LOADs / STOREs) and log the results into _results/<fuzz_timestamp>_/. 
```bash
python3 fuzzer.py -n 10 -p 30 -m 10 --debug
```
#### The Fuzzer's Process
In each fuzzing round, **fuzzer.py** runs a testcase along with n_inputs random inputs, for n_reps times, and collects 
measurement traces which look like the following: 
```text
  [0,0]: <counter_1 value> ... <counter_n value>
  [0,1]: <counter_1 value> ... <counter_n value>
    .
    .
    .
  [n_reps,n_inputs] <counter_1 value> ... <counter_n value>
```
Then, the traces are passed to **analyzer.py** which analyzes the measurements and tries to find "violations". 
In this context, a "violation" is a five-tuple _(Ii,Ij,C,dt,df)_ where:
 - _Ii,Ij_ are input indices (e.g 0 and 2)
 - _C_ is a specific counter 
 - _dt_ is a value in [0,1] which determines what is the minimal **difference** in percentages between _Ii_'s and _Ij_'s measurements of _C_, that is considered "interesting" (=not ignored).
 - _df_ is a value in [0,1] which determines the minimal **frequency** in which an "interesting" difference must occur, to not be ignored by **analyzer.py**.
   
In short, a violation is 2 inputs which frequently differ in some counter, by a meaningful amount.

If **analyzer.py** finds violations, they are all declared and the fuzzing stops. 
If no violations were found, the fuzzer continues for the next testacse. 

Reported violations look like the following: 
```text
  [V]:(0, 1) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 2) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 3) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 4) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 5) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 6) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 7) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 8) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 9) | CPU_CLK_UNHALTED.THREAD_P | 1.0
  [V]:(0, 1) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 2) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 3) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 4) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 5) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 6) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 7) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 8) | ARITH.DIV_ACTIVE | 1.0
  [V]:(0, 9) | ARITH.DIV_ACTIVE | 1.0
```
In this case, the test included a **DIV** instruction which has a variable-latency.

As we can see, the 1st input achieved a consistently different cycle count and 
cycles during which the divide unit is active, which are counted by
CPU_CLK_UNHALTED.THREAD_P and ARITH.DIV_ACTIVE respectively. 

This teaches us that this input induces a significantly slower / faster flow than 
inputs 1-9. 

### Useful Flags
| Argument                  | Type     | Default              | Description                                               |
|---------------------------|----------|----------------------|-----------------------------------------------------------|
| `-n`, `--num-test-cases`  | `int`    | `10`                 | Number of test cases to generate                          |
| `-p`, `--program-size`    | `int`    | `30`                 | Number of instructions per test case                      |
| `-core`, `--core-id`      | `int`    | `2`                  | Logical ID of the core that will run the tests            |
| `-m`, `--mem-accesses`    | `int`    | `10`                 | Number of memory accesses per test case                   |
| `-S`, `--scale-factor`    | `float`  | `1.1`                | Scale of parameters growth between test cases             |
| `-dt`, `--diff-threshold` | `float`  | `0.5`                | Difference threshold for the analyzer                     |
| `-ft`, `--freq-threshold` | `float`  | `0.5`                | Frequency threshold for the analyzer                      |
| `-s`, `--seed`            | `int`    | `123456789`          | Seed for random generation                                |
| `-w`, `--warmup-count`    | `int`    | `1`                  | Number of warmup rounds before each experiment            |
| `-a`, `--aggregate-func`  | `str`    | `"avg"`              | Aggregation function: `avg`, `min`, `max`, or `median`    |
| `-conf`, `--config-file`  | `str`    | `None`               | Path to performance counters configuration file           |
| `-i`, `--instruction-spec`| `str`    | `utils/base.json`    | JSON file with instruction definitions                    |
| `-f`, `--instruction-filter` | `str` | `utils/doits.txt`    | Text file listing allowed instructions                    |
| `-o`, `--out-directory`   | `str`    | `results/`           | Directory for saving test output                          |
| `-D`, `--debug`           | `flag`   | `False`              | Enable debug mode (stores all test artifacts)             |
| `-P`, `--plot`            | `flag`   | `False`              | Enable plotting of results                                |

### Logging and Reproducibility 
Adding the _-debug_ flag logs important information about the fuzz which can later be used to reproduce the results:
1. The configuration of the fuzz can be viewed in _results/<fuzz_timestamp>_/fuzz.params:
```text
  Fuzzer Configuration:

  Test Cases      : 10
  Instructions    : 662 loaded from <instruction json>
  Filter          : <optional filter of the instructions in the json>
  Program Size    : 40
  Memory Accesses : 10
  Scale Factor    : 1.1
  Diff. Threshold : 0.5
  Freq. Threshold : 0.5
  Seed            : 123456789
  Warmup Count    : 2
  Config File     : <counters configuration text file>
  Core ID         : 16
  Output Dir      : <root/results>
```
Notice that some parameters have default values,

for all the full list see **FuzzerConfig** inside **fuzzer.py**.

2. The generated tests themselves can be viewed in _results/<fuzz_timestamp>_/test<num_test>.asm
   
3. The PFC measurements for each test can also be viewed in _results/<fuzz_timestamp>_/test<num_test>_<n_reps>reps.res 





