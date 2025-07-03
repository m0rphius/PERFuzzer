"""
Analyzer - analyzes the output of fuzzing rounds to find violations
"""

from typing import List, Tuple
from dataclasses import dataclass
from itertools import combinations
import numpy as np
from tqdm import tqdm, TqdmWarning
from abc import ABC, abstractmethod
from collections import Counter
from scipy import stats
from statistics import quantiles, median
from pathlib import Path

import warnings
warnings.filterwarnings("ignore", category=TqdmWarning, module="tqdm")

from fuzzer import Input
from utils import (
    write_inputs,
    makedirs,
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
    """A trace of measurements for a specific counter"""

    def __init__(self, cname : str, trace : List[int]):
        self.cname = cname
        self.trace = trace.copy()


class AnalyzerError(Exception): 
    """Custom exception for Analyzer errors"""
    pass


class Analyzer(ABC):

    def __init__(self):
        # A cache to hold the results of priming experiments (lowers amount of runs)
        self.priming_cache = {}
        self.violations = []

    from fuzzer import FuzzerConfig
    def analyze(self, fuzzer_output : str, test_code : str, test_num : int, inputs : List[Input], 
                config : FuzzerConfig, n_reps : int, n_inputs : int, memory_binary : List[int]):
        """  
        Analyze an entire fuzzing round trace and search for violations

        :param fuzzer_output: the output of an entire fuzzing round (described in __create_fuzzing_round_trace)
        :param test_code: the code that was ran
        :param inputs: the constant and variable inputs that were fed to the code
        :param config: the fuzzer configuration (used in the fuzzing round) 
        :param n_reps: number of experiments in the round
        :param n_inputs: number of inputs in each experiment

        """
        fuzzing_round_trace : List[List[CounterTrace]] = self.__create_fuzzing_round_trace(fuzzer_output, config, n_inputs)
        inputs_pairs = list(combinations(range(n_inputs), 2))
        assert len(inputs_pairs) == n_inputs * (n_inputs - 1) / 2 # nCr(n_inputs,2)

        # For priming
        self.priming_cache.clear()

        found = 0
        violations_dir = Path(str(config.out_directory) + "/violations") # Only opened if found violations
        violations_str = ""
        with tqdm(total=config.n_counters * len(inputs_pairs), desc="analyzing results", colour="green") as pbar:
            for counter, counter_traces in enumerate(fuzzing_round_trace): 
                for i, (Ii, Ij) in enumerate(inputs_pairs):
                    ctrace_Ii = counter_traces[Ii]
                    ctrace_Ij = counter_traces[Ij]

                    # Differences above thresholds
                    if not self.compare_ctraces(ctrace_Ii, ctrace_Ij) and \
                       (not self.__prime(test_code, n_reps, n_inputs, config, inputs, (Ii,Ij), counter)):
                        violations_str += f"{Bcolors.FAIL}[V] {Bcolors.ENDC}{(Ii,Ij)} | {config.counter_ids[counter]}\n"
                        if config.verbose:
                            pretty_violation = self.__traces_pretty_print(ctrace_Ii, ctrace_Ij)
                            violations_str += pretty_violation + "\n"
                            if config.debug:
                               makedirs(violations_dir / str(test_num))
                               violation_file = violations_dir / f"{Ii}_{Ij}_{ctrace_Ii.cname}"
                               mem_image_file = violations_dir / "mem.bin"
                               with open(mem_image_file, "wb") as f:
                                   for v in memory_binary:
                                       f.write(int(v).to_bytes(length=1, byteorder="little"))
                               with open(violation_file, "w") as f:
                                   f.write(f"{inputs[config.warmup_count + Ii]}\n{inputs[config.warmup_count + Ij]}\n\n" \
                                           f"{pretty_violation}")

                        found += 1
                    pbar.update(1)

        if found != 0:
            print(violations_str)

        return found

    def __create_fuzzing_round_trace(self, fuzzer_output : str, config : FuzzerConfig, n_inputs : int) \
    -> List[List[CounterTrace]]:
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
        
        traces : List[List[CounterTrace]] = [[CounterTrace(config.counter_ids[i], []) for _ in range(n_inputs)] \
                                              for i in range(config.n_counters) ]

        for i, line in enumerate(lines): 
            measurements = line.split()[1:] # First element is "[_,_]:"
    
            for j, m in enumerate(measurements): 
                traces[j][i % n_inputs].trace.append(int(m))

        # print("TRACES: ", len(traces))
        # print("TRACE: ", len(traces[0][0].trace))
        return traces

    def __prime(self, test_code : str, n_reps : int, n_inputs : int, config : FuzzerConfig, 
                inputs : List[Input], pair : Tuple[int, int], 
                counter : int) -> bool: 
        id1 = pair[0]
        id2 = pair[1]

        temp = self.priming_cache.get((id1, id2), None)

        if temp: # "Hit"
            output12 = temp[0]
            output21 = temp[1]
        else:
            # Version 1: id1 <- id2
            inputs12 = inputs.copy()
            for rep in range(n_reps):
                inputs12[rep*(config.warmup_count + n_inputs) + config.warmup_count + id1] = \
                      inputs12[rep*(config.warmup_count + n_inputs) + config.warmup_count + id2]
            
            write_inputs(inputs12)

            # Configure experiment
            initialize_experiment(
                config=config.config_file,
                num_inputs=n_inputs,
                seed=config.seed,
                cpu=config.core_id,
                aggregate_func=config.aggregate_func,
                warmup_count=config.warmup_count
            )

            output12 = ""
            with open("/sys/FuzzerBench/trace", 'rb') as trace:
                for rep in range(n_reps):
                    try:
                        output12 += trace.read().decode('utf-8')
                        trace.seek(0)
                    except Exception as e:
                        raise AnalyzerError(f"Error in priming: {e}")
            
            # Version 2: id2 <- id1
            inputs21 = inputs.copy()
            for rep in range(n_reps):
                inputs21[rep*(config.warmup_count + n_inputs) + config.warmup_count + id2] = \
                      inputs21[rep*(config.warmup_count + n_inputs) + config.warmup_count + id1]

            write_inputs(inputs21)

            # Configure experiment
            initialize_experiment(
                config=config.config_file,
                num_inputs=n_inputs,
                seed=config.seed,
                cpu=config.core_id,
                aggregate_func=config.aggregate_func,
                warmup_count=config.warmup_count
            )

            output21 = ""
            with open("/sys/FuzzerBench/trace", 'rb') as trace:
                for rep in range(n_reps):
                    try:
                        output21 += trace.read().decode('utf-8')
                        trace.seek(0)
                    except Exception as e:
                        raise AnalyzerError(f"Error in priming: {e}")
                
            self.priming_cache[(id1,id2)] = (output12, output21)

        # Extract CounterTraces
        traces12 : List[List[CounterTrace]] = self.__create_fuzzing_round_trace(output12, config, n_inputs)
        traces21 : List[List[CounterTrace]] = self.__create_fuzzing_round_trace(output21, config, n_inputs)

        # Check id2 at id1 vs. id1 at id1
        traces12_id1 = traces12[counter][id1]
        traces21_id1 = traces21[counter][id1]

        if not self.compare_ctraces(traces12_id1, traces21_id1):
            return False

        # Check id1 at id2 vs. id2 at id2
        traces21_id2 = traces21[counter][id2]
        traces12_id2 = traces12[counter][id2]

        return self.compare_ctraces(traces21_id2, traces12_id2)


    @abstractmethod
    def compare_ctraces(self, t1 : CounterTrace, t2 : CounterTrace) -> bool:
        """ Conduct equality testing between two CounterTraces """
        pass

    def remove_outliers(self, trace : List[int], method : str = "mad") -> List[int]:
        """ Remove outliers using the IQR method """
        if method == "iqr":
            return self.__iqr_filter(trace)
        elif method == "mad":
            return self.__mad_filter(trace)
        
        return None

    def __iqr_filter(self, trace : List[int]) -> List[int]:
        quants = quantiles(trace, n=4)
        q1 = quants[0]
        q3 = quants[2]
        iqr = q3 - q1

        l = q1 - 1.5 * iqr
        r = q3 + 1.5 * iqr
        res = [v for v in trace if v >= l and v <= r]
        return res

    def __mad_filter(self, trace : List[int]) -> List[int]: 
        m = median(trace)
        devs = [abs(v - m) for v in trace]
        mad = median(devs)

        res = [v for (i,v) in enumerate(trace) if devs[i] <= 3 * mad]
        return res
    
    def __traces_pretty_print(self, t1 : CounterTrace, t2 : CounterTrace):
        """ Print the traces in an eye-friendly format """
        c1 = Counter(t1.trace)
        c2 = Counter(t2.trace)
        widths = [8, 9, 9]  # Define column widths

        def line(char="-", joint="+"):
            return joint + joint.join(char * w for w in widths) + joint + '\n'

        def row(values):
            return "| " + " | ".join(f"{v:>{w-2}}" for v, w in zip(values, widths)) + " |\n"

        res = line("-", "+")
        res += row(["Value", "Trace 1", "Trace 2"])
        res += line("-", "+")

        all_keys = sorted(set(c1) | set(c2))
        for k in all_keys:
            v1 = c1.get(k, 0)
            v2 = c2.get(k, 0)

            res += row([k, v1, v2])
        
            res += line("-", "+")
        return res

class ChiAnalyzer(Analyzer):
    """
    Analysis is based on comparing CounterTraces using the Chi-Square test. 

    In this context, violations are any two inputs (Ii,Ij) s.t the 
    CounterTraces (C_Ii, C_Ij) aren't from the same distribution (according to Chi-Square test)

    """
    def __init__(self, stat_threshold : float = 0.5, outliers_threshold : float = 0.2):
        super().__init__()
        self.stat_threshold = stat_threshold
        self.outliers_threshold = outliers_threshold
    
    def compare_ctraces(self, t1 : CounterTrace, t2 : CounterTrace) -> bool:
        """ Use the Chi-Square test to compare CounterTraces """
        assert len(t1.trace) == len(t2.trace), "Traces aren't compatible!"

        # Filter outliers
        filtered_combined : List[int] = self.remove_outliers(t1.trace + t2.trace, method="mad")
        t1_filtered = [x for x in t1.trace if x in filtered_combined]
        t2_filtered = [x for x in t2.trace if x in filtered_combined]
        
        # t1_filtered = t1.trace
        # t2_filtered = t2.trace

        # Shouldn't get here
        assert len(t1_filtered) != 0 and len(t2_filtered) != 0
        
        counter1 = Counter(t1_filtered)
        counter2 = Counter(t2_filtered)
        keys = sorted(set(counter1) | set(counter2))

        obs1 = [counter1.get(k, 0) for k in keys]
        obs2 = [counter2.get(k, 0) for k in keys]

        contingency_table = [obs1, obs2]  # Rows: groups, Columns: categories

        chi2, _, _, _ = stats.chi2_contingency(contingency_table)

        chi2 = chi2 / (len(t1_filtered) + len(t2_filtered))
        # Return True if the two traces are statistically similar
        return chi2 < self.stat_threshold


class ThresholdAnalyzer(Analyzer): 
    """ 
    Analysis is based on thresholds, specifically: 

    difference_threshold: analyser will ignore counter differences smaller than 
                          difference_threshold percentages.
                          I.e, a difference d=|ctr1-ctr2| passes the filter if 
                          (d/max(ctr1,ctr2)) > difference_threshold
                            
    frequency_threshold: analyser will only analyze triples (Ik,Ij,c) where Ik,Ij are inputs,
                         c is a counter for which Ik,Ij pass the difference threshold for more 
                         than frequency_threshold * n_reps experiments. 
    """

    def __init__(self, difference_threshold : int = 0.5, frequency_threshold : int = 0.5):
        """

        :param difference_threshold: analyser will ignore counter differences smaller than 
        difference_threshold percentages.
        I.e, a difference d=|ctr1-ctr2| passes the filter if (d/max(ctr1,ctr2)) > difference_threshold
        
        :param frequency_threshold: analyser will only analyze triples (Ik,Ij,c) where Ik,Ij are inputs,
        c is a counter for which Ik,Ij pass the difference threshold for more than frequency_threshold * n_reps 
        experiments. 

        """
        super().__init__()
        self.difference_threshold = difference_threshold
        self.frequency_threshold = frequency_threshold
        
    
    def compare_ctraces(self, t1 : CounterTrace, t2 : CounterTrace) -> bool:
        """ Use threshold testing to comapre CounterTraces """
        assert len(t1.trace) == len(t2.trace), "Traces aren't compatible!"
        n_reps = len(t1.trace)

        # If one of the values is 0, measure pure diff
        max_vals = [max(m1, m2) if m1 != 0 and m2 != 0 else 1 for (m1,m2) in zip(t1.trace, t2.trace)]
        diffs = [abs(m1 - m2) / max_vals[i] for i, (m1,m2) in enumerate(zip(t1.trace, t2.trace))]
        diffs_count = [1 for diff in diffs if diff > self.difference_threshold]
        freq = sum(diffs_count) / n_reps

        return freq <= self.frequency_threshold
    