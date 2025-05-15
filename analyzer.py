import os
from argparse import ArgumentParser, ArgumentTypeError
from typing import List
import numpy as np
import math
from utils.utils import pfcs_names_p, pfcs_names_e
import matplotlib.pyplot as plt
import sys

pfcs_names = []

# Parse a test<i>_<j>inputs.res file and compute statistics for each counter
def compute_statistics(results_filename : str, core_id : int = 0):
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
                input_group = int(line[len("Input group "):]) # For mean and variance
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
def plot_statistics(pfcs_info, outfile):

    # Sort by mean
    sorted_pfc = sorted(pfcs_info.items(), key=lambda x: x[0], reverse=True)
    sorted_pfc = [p for p in sorted_pfc if p[1]['mean'] > 0.0]
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
    

# For individual results analysis
if __name__ == "__main__":
    # ====================================================================================
    # Parse arguments
    parser = ArgumentParser(add_help=True)
    # parser.add_argument("-f",
    #     "--results-file",
    #     type=str,
    #     required=True,
    #     help="The results file to analyze.",
    #    )
    parser.add_argument("-t",
         "--test",
        type=str,
        required=True,
        help="The test to analyze.",
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
    results_file = f"tmp/{args.test}.res"
    testname = args.test
    core_id = args.core_id
    plot = args.plot
    # =====================================================================================
    # verify arguments

    if not os.path.exists(results_file):
        print(f"[Error] {results_file} does not exist.")
        exit(1)
    if not os.path.isfile(results_file):
        print(f"[Error] {results_file} is not a file.")
        exit(1)
    if core_id < 0 or core_id > 19:
        print(f"[Error] {core_id} is not a valid core ID.")
        exit(1)
    if core_id in range(0, 16):
        pfcs_names = pfcs_names_p
    else:
        pfcs_names = pfcs_names_e
    
    # =====================================================================================
    # Compute statistics (plot if requested)
    
    pfcs_info = compute_statistics(results_file, core_id)
    if plot:
        plot_outfile = f"tmp/{testname}.png"
        plot_statistics(pfcs_info, plot_outfile)
    else:
        for pfc_name in pfcs_info.keys():
            print(f"{pfc_name}:\n[\nAVG={pfcs_info[pfc_name]['mean']}\nVAR={pfcs_info[pfc_name]['var']}\nSTDDEV={pfcs_info[pfc_name]['stddev']}\nMIN={pfcs_info[pfc_name]['min']}\nINPUTS={pfcs_info[pfc_name]['min_ind']}\nMAX={pfcs_info[pfc_name]['max']}\nINPUTS={pfcs_info[pfc_name]['max_ind']}\n]\n")
