"""
Analyzer - analyzes the output of fuzzing rounds to find violations
"""

from typing import List, Tuple
from dataclasses import dataclass
from itertools import combinations
import numpy as np
from tqdm import tqdm

from fuzzer import VarInput
from utils import (
    write_inputs,
    initialize_experiment
)

class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class CounterTrace:
    """A trace of measurements for a specific"""

    def __init__(self, cname : str, trace : List[List[float]]):
        self.cname = cname
        self.trace = trace.copy()

class AnalyzerError(Exception): 
    """Custom exception for Analyzer errors"""
    pass

class Analyzer: 
    """ Analyses the output of a fuzzing round and tries to find violations"""


    def __init__(self, difference_threshold : int = 0.5, frequency_threshold : int = 0.5):
        """
        :param experiment_output: the output of an entire fuzzing round
        :param config: the fuzzer configuration (used in the fuzzing round) 
        :param n_reps: number of experiments in the round
        :param n_inputs: number of inputs in each experiment

        :param difference_threshold: analyser will ignore counter differences smaller than 
        difference_threshold percentages.
        I.e, a difference d=|ctr1-ctr2| passes the filter if (d/max(ctr1,ctr2)) > difference_threshold
        
        :param frequency_threshold: analyser will only analyze triples (Ik,Ij,c) where Ik,Ij are inputs,
        c is a counter for which Ik,Ij pass the difference threshold for more than frequency_threshold * n_reps 
        experiments. 

        """
        self.difference_threshold = difference_threshold
        self.frequency_threshold = frequency_threshold
        
    from fuzzer import FuzzerConfig
    def analyze(self, fuzzer_output : str, test_code : str, inputs : Tuple[List[int], List[VarInput]], 
                config : FuzzerConfig, n_reps : int, n_inputs : int):

        fuzzing_round_trace : List[CounterTrace] = self.__create_fuzzing_round_trace(fuzzer_output, config, n_inputs)
        inputs_pairs = list(combinations(range(n_inputs), 2))
        assert len(inputs_pairs) == n_inputs * (n_inputs - 1) / 2 # nCr(n_inputs,2)

        found = 0
        desc = (f"Analyzing counters ")
        violations = ""
        with tqdm(total=config.n_counters, desc=desc, colour="red") as pbar:
            for counter, counter_trace in enumerate(fuzzing_round_trace): 
                
                interesting_diffs_counts = self.__analyze_pairs_and_counter(counter_trace,
                                                                        inputs_pairs,
                                                                        n_reps,
                                                                        n_inputs)
                for i, count in enumerate(interesting_diffs_counts):
                    # print(count)
                    freq : float = count / n_reps
                    pair = inputs_pairs[i]

                    if freq > self.frequency_threshold:
                        # TODO: reproducibility test
                        if self.__reproducibility_test(test_code, config, inputs, n_reps, pair, counter):
                            violations += f"{Bcolors.FAIL}[V]:{Bcolors.ENDC}{inputs_pairs[i]} | {counter_trace.cname} | {freq}"
                            found += 1

                    pbar.update(1/len(interesting_diffs_counts))
                
            
        if found == 0:
            print("Found no violations")
        else:
            print(violations)

        return found
    
    def __create_fuzzing_round_trace(self, fuzzer_output : str, config : FuzzerConfig, n_inputs : int) \
    -> List[CounterTrace]:
        """ A single experiment is one run of all n_inputs with n_counters measurements for each input, i.e: 
        [1]: pfc1 pfc2 ... pfcn
        [2]: pfc1 pfc2 ... pfcn
        .
        .
        .
        [n_inputs]: pfc1 ... pfcn  
        
        A fuzzing round trace is n_reps of singles experients, I.e: 
        [0,1]: pfc1 pfc2 ... pfcn
        [0,2]: pfc1 pfc2 ... pfcn
        .
        .
        .
        [n_reps,n_inputs]: pfc1 ... pfcn  

        """
        lines = fuzzer_output.splitlines()
        
        traces : List[CounterTrace] = [CounterTrace(config.counter_ids[i], []) for i in range(config.n_counters)]

        for i, line in enumerate(lines): 
            measurements = line.split()[1:] # First element is "[_,_]:"
            
            for j, m in enumerate(measurements): 
                if i % n_inputs == 0: # Start a new rep list
                    traces[j].trace.append([])
                traces[j].trace[-1].append(float(m))

        return traces
    
    def __analyze_pairs_and_counter(self, counter_trace : CounterTrace, inputs_pairs : List[Tuple[int,int]], 
                                   n_reps : int, n_inputs : int):
        # For efficiency
        counter_trace_np = np.array(counter_trace.trace)

        # Pairwise diff percentage
        pairwise_diffs_np = np.zeros((n_reps, len(inputs_pairs)), dtype=float)

        for i, (Ik, Ij) in enumerate(inputs_pairs):
            A = counter_trace_np[:, Ik]
            B = counter_trace_np[:, Ij]
            max_vals = np.maximum(A,B)
            diffs = np.abs(A - B)

            with np.errstate(divide='ignore', invalid='ignore'):
                # Divide only where max != 0
                result = np.divide(diffs, max_vals, out=np.zeros_like(diffs, dtype=float), where=(max_vals != 0))
            
            pairwise_diffs_np[:, i] = result

        # Filter "interesting" diffs
        pairwise_diffs_np[~(pairwise_diffs_np > self.difference_threshold)] = 0
        interesting_diffs_counts = np.count_nonzero(pairwise_diffs_np, axis=0)

        return interesting_diffs_counts

    def __reproducibility_test(self, 
                               test_code : str, 
                               config : FuzzerConfig, 
                               inputs : Tuple[List[int], List[VarInput]],
                               n_reps : int,
                               pair : Tuple[int], 
                               counter : int
                               ):
        """"Try and reproduce the violation between both inputs alone
        
        param: test_code: the original code which induced the violation
        param: config: the configuration of the violating test
        param: inputs: the inputs to the code
        param: n_reps: the number of reps performed in the original test
        param: pair: 2 inputs which showed a violation
        param: counter: the counter index in which the violatin occured

        """

        constant_inputs, variable_inputs = inputs
        input_id1 = pair[0]
        input_id2 = pair[1]
        input1 = variable_inputs[config.warmup_count + input_id1]
        input2 = variable_inputs[config.warmup_count + input_id2]
        warmup_inputs = variable_inputs[:config.warmup_count]
        tested_inputs_temp = warmup_inputs + [input1, input2]
        
        tested_inputs = []
        for _ in range(n_reps):
            tested_inputs += tested_inputs_temp
        
        assert len(input1.values) == len(input2.values), "Inputs are illgal!"

        # Start experiment
        formatted_code = f'"{test_code}"'
        initialize_experiment(testcase=formatted_code)


        write_inputs(constant_inputs, tested_inputs)
        
        initialize_experiment(
            config=config.config_file,
            num_inputs=2,
            seed=config.seed,
            cpu=config.core_id,
            aggregate_func=config.aggregate_func,
            warmup_count=config.warmup_count
        )

        fuzzer_output = ""
        with open("/sys/FuzzerBench/trace", 'rb') as trace:
            for _ in range(n_reps):
                try:
                    fuzzer_output += trace.read().decode('utf-8')
                    trace.seek(0)
                except Exception as e:
                    raise AnalyzerError(f"[ERROR] analyzer: while trying to reproduce {e}")

        fuzzing_round_trace : List[CounterTrace] = self.__create_fuzzing_round_trace(fuzzer_output, config, 2) # Only 2 inputs
        inputs_pairs = [(0,1)] # Only one pair 
        counter_trace = fuzzing_round_trace[counter]

        interesting_diffs_counts = self.__analyze_pairs_and_counter(counter_trace, inputs_pairs, n_reps, 2)

        # Only one pair
        count = interesting_diffs_counts[0]
        freq : float = count / n_reps

        return freq > self.frequency_threshold    
