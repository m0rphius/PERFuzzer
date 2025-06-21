# PERFuzzer

**PERFuzzer** is a hardware-oriented instruction fuzzer designed to explore subtle behaviors in CPU microarchitecture using performance counters.  
Built on top of a custom kernel module called **FuzzBench** (a fork of nanoBench), it automates the generation, execution, and analysis of randomized instruction sequences to detect timing anomalies and microarchitectural side effects.

---

## Highlights

- Performance-counter-driven fuzzing
- Systematic exploration of instruction interactions
- Kernel module for accurate in-core measurements
- Input-controlled microbenchmarking (RAX, RBX, RCX, RDX)
- Scalable fuzzing with dynamic test generation and thresholds

---

## Architecture

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
In this context, a "violation" is a five-tuple (Ii,Ij,c)_,dt,df_ where:
 - _Ii,Ij_ are input indices (e.g 0 and 2)
 - _c_ is a specific counter
 - _dt_ is a value in [0,1] which determines 
which differ in measurement by some minimal threshold, 

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
This is useful for reproducing results from a previous fuzz. 
Notice that some parameters have default values, for all the default values see the definition of the **FuzzerConfig** class inside **fuzzer.py**.
2. The tests themselves can be viewed in _results/<fuzz_timestamp>_/test<num_test>.asm
3. The PFC measurements for each test can also be viewed in _results/<fuzz_timestamp>_/test<num_test>_<n_reps>reps.res
which look like the following: 

where **n_reps** and **n_inputs** are the number of times we repeat each test and the number of random inputs for each test, respectively. 




