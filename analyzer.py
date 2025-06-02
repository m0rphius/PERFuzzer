from itertools import combinations
import os
from argparse import ArgumentParser
import math
from sre_constants import ASSERT
from utils.utils import pfcs_names_p, pfcs_names_e
import matplotlib.pyplot as plt
from tqdm import tqdm
from typing import List, Tuple
import numpy as np

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

pfcs_names = []

def _compute_diff_histogram(output : str, n_inputs : int) -> Tuple[np.ndarray[np.float32], List[Tuple]]:
    # Prepare histogram: each element represents a pair (Ii,Ij) of 2 inputs
    # and contains a list of counters of size <n_pfc_configs>, which counts differences in each counter.
    results = [l for l in output.split('\n') if l.startswith("[")]
    results_by_reps = []
    rep_list = []
    for i in range(len(results)):
        # Start a new rep list
        if i != 0 and i % n_inputs == 0:
            results_by_reps.append(rep_list)
            rep_list = []
        rep_list.append([float(n) for n in results[i].split()[1:]])
    
    # Continue with numpy for efficiency
    x = np.array(results_by_reps, dtype=np.float32)
    B, H, W = x.shape
    pairs = list(combinations(range(H), 2)) # Note: pairs are sorted in lex-order.  
    # will contain the differences
    diffs = np.empty((B, len(pairs), W), dtype=np.float32)
    
    for idx, (i, j) in enumerate(pairs):
        diffs[:, idx, :] = x[:, i, :] - x[:, j, :]
    diffs = np.round(np.abs(diffs), 2)
    
    return diffs, pairs


def analyze_results_str(output : str = None, n_reps : int = 0, n_inputs : int = 0, violation_threshold : float = 0.0):

    if output == None:
        print(f"[Error] no output provided!.")
        exit(1)

    # Get configs
    with open("/sys/nb/config", "r") as f:
        configs = [l.split()[1] for l in f.readlines()]

    n_pfc_configs = len(configs)

    diffs, pairs = _compute_diff_histogram(output, n_inputs)
    H = len(pairs)
    W = n_pfc_configs
    x = np.empty((H, W))

    final = ""
    for i in range(H):
        x[i] = np.sum(diffs[:, i, :] > violation_threshold, axis=0)
        violations = np.argwhere(x[i])
        if violations.size != 0:
            for ind in violations:
                ind = ind.item()
                final += f"{pairs[i]} {x[i][ind]} {configs[ind]}\n"
    return final
    # Search for violations


# Parse a test<i>_<j>inputs.res file and compute statistics for each counter
def _compute_statistics(results_filename : str, core_id : int = 0):
    if core_id in range(0,16):
        pfcs_names = pfcs_names_p
    else:
        pfcs_names = pfcs_names_e

    pfcs_info = {pfc: {'mean': 0.0, 'var': 0.0, 'stddev': 0.0, 'n': 0, 'min': math.inf, 'min_ind': 0, 'max': -math.inf, 'max_ind': 0} for pfc in pfcs_names}
    # Read file
    with open(results_filename, "r") as f:
        lines = f.readlines()
        for line in lines:
            if line == "\n" or line == "":
                continue
            elif line.startswith("Input group"):
                after_num = line.find(':')
                input_group = int(line[len("Input group "):after_num]) # For mean and variance
                continue
            else: 
                words = line.split()
                pfc = words[0][:-1]
                # If counter line, first word without ":" is a valid key
                if pfcs_info.get(pfc, None) == None:
                    continue
                # print(f"pfc={pfc}")
                pfcs_info[pfc]['n'] += 1
                n = pfcs_info[pfc]['n']
                value = float(words[1])
                mean = pfcs_info[pfc]['mean']
                var = pfcs_info[pfc]['var']
                min = pfcs_info[pfc]['min']
                max = pfcs_info[pfc]['max']

                # Update values
                delta = value - mean
                mean += delta / n
                delta2 = value - mean
                var += delta * delta2
                pfcs_info[pfc]['mean'] = mean
                pfcs_info[pfc]['var'] = var
                
                if value < min:
                    pfcs_info[pfc]['min'] = value
                    pfcs_info[pfc]['min_ind'] = input_group

                if value > max:
                    pfcs_info[pfc]['max'] = value
                    pfcs_info[pfc]['max_ind'] = input_group

    for pfc_name in pfcs_info.keys():
            temp = pfcs_info[pfc_name]['var']
            n = pfcs_info[pfc_name]['n']
            pfcs_info[pfc_name]['var'] = temp/(n - 1)
            pfcs_info[pfc_name]['stddev'] = math.sqrt(temp/(n - 1))
            
    return pfcs_info

# Plot the statistics
def _plot_statistics(pfcs_info, outfile):

    # Sort by mean
    sorted_pfc = sorted(pfcs_info.items(), key=lambda x: x[0], reverse=True)
    sorted_pfc = [p for p in sorted_pfc if p[1]['min'] != math.inf]
    pfc_names = [p[0] for p in sorted_pfc]
    means = [p[1]['mean'] for p in sorted_pfc]
    stddevs = [p[1]['stddev'] for p in sorted_pfc]
    mins = [p[1]['min'] for p in sorted_pfc]
    maxs = [p[1]['max'] for p in sorted_pfc]

    # Plotting
    plt.figure(figsize=(14, len(pfc_names) * 0.4))
    y_pos = range(len(pfc_names))

    # Horizontal bar plot for means
    plt.barh(y_pos, means, color='lightblue', alpha=0.7, edgecolor='k', label='Mean')

    # Error bars (stddev)
    plt.errorbar(means, y_pos, xerr=stddevs, fmt='none', ecolor='darkblue', elinewidth=1.5, capsize=5, label='Stddev')

    # Min points
    plt.scatter(mins, y_pos, color='blue', marker='x', s=100, label='Min')

    # Max points
    plt.scatter(maxs, y_pos, color='red', marker='x', s=100, label='Max')

    # Labels and formatting
    plt.yticks(y_pos, pfc_names)
    plt.xlabel('Values')
    plt.title('PFC Counters: Mean, Stddev, Min, Max (Cleaned View)')
    plt.grid(axis='x', linestyle='--', alpha=0.3)
    plt.legend()
    plt.tight_layout()

    plt.show()
    plt.savefig(outfile, dpi=300, bbox_inches='tight')

def analyze_results_dir(fuzz_dir : str=None, testfile : str=None, plot : bool=0, core_id : int=0):
    if core_id < 0 or core_id > 19:
        print(f"[Error] {core_id} is not a valid core ID.")
        exit(1)
    if core_id in range(0, 16):
        pfcs_names = pfcs_names_p
    else:
        pfcs_names = pfcs_names_e

    if fuzz_dir != None:
        if not os.path.exists(fuzz_dir):
            print(f"[Error] {fuzz_dir} does not exist.")
            exit(1)
        if not os.path.isdir(fuzz_dir):
            print(f"[Error] {fuzz_dir} is not a directory.")
            exit(1)
    elif testfile != None:
        if not os.path.exists(testfile):
            print(f"[Error] {testfile} does not exist.")
            exit(1)
        if not os.path.isfile(testfile):
            print(f"[Error] {testfile} is not a file.")
            exit(1)
    else:
        print(f"[Error] no fuzz dir or results file provided!.")
        exit(1)
    
    if fuzz_dir != None:
        filenames = [s for s in os.listdir(fuzz_dir) if s.endswith('.res')]
        for filename in tqdm(filenames, desc="Analyzing results"):
            path = f"{fuzz_dir}/{filename}"
            pfcs_info = _compute_statistics(path, core_id)
            if plot:
                plot_outfile = f"{fuzz_dir}/{filename[:-4]}.png"
                _plot_statistics(pfcs_info, plot_outfile)
            stats_outfile = f"{fuzz_dir}/{filename[:-4]}.stats"
            pfcs = [pfc for pfc in pfcs_info.items() if pfc[1]['min'] != math.inf]
            with open(stats_outfile, "w") as f:
                for (name, desc) in pfcs:
                    f.write(f"{name}:\n[\nAVG={desc['mean']}\nVAR={desc['var']}\nSTDDEV={desc['stddev']}\nMIN={desc['min']}\nINPUTS={desc['min_ind']}\nMAX={desc['max']}\nINPUTS={desc['max_ind']}\n]\n\n")
    elif testfile != None:
        pfcs_info = _compute_statistics(testfile, core_id)
        if plot:
            plot_outfile = f"{testfile[:-4]}.png"
            _plot_statistics(pfcs_info, plot_outfile)
        stats_outfile = f"{testfile[:-4]}.stats"
        pfcs = [pfc for pfc in pfcs_info.items() if pfc[1]['min'] != math.inf]
        with open(stats_outfile, "w") as f:
            for (name, desc) in pfcs:
                f.write(f"{name}:\n[\nAVG={desc['mean']}\nVAR={desc['var']}\nSTDDEV={desc['stddev']}\nMIN={desc['min']}\nINPUTS={desc['min_ind']}\nMAX={desc['max']}\nINPUTS={desc['max_ind']}\n]\n\n")

# For individual results analysis
if __name__ == "__main__":
    # ====================================================================================
    # Parse arguments
    parser = ArgumentParser(add_help=True)
    parser.add_argument("-d",
         "--fuzz-dir",
        type=str,
        required=False,
        help="A fuzz directory to analyze.",
       )
    parser.add_argument("-t",
         "--test-file",
        type=str,
        required=False,
        help="A test results to analyze.",
       )
    parser.add_argument("-c",
        "--core-id",
        type=int,
        default=0,
        help="The core ID to analyze.",
       )
    parser.add_argument("-p",
        "--plot",
        action="store_true",
        help="Plot the statistics (if not specified, stats are printed).",
       )
    
    args = parser.parse_args()
    core_id = args.core_id
    plot = args.plot
    # =====================================================================================
    # analyze
    analyze_results_dir(args.fuzz_dir, args.test_file, plot)
