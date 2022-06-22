'''
This file concatenates multiples .json files into one parsed .txt file
'''

import json
import pandas as pd

versions = ["latest", "stable", "0.4", "0.5", "0.6"]
files = ["results-v_latest.json", "results-v_stable.json", "results-v0.4.json", "results-v0.5.json", "results-v0.6.json"]
binaries = pd.read_json('binaries.json')
size = len(binaries)

with open('parsed_results.txt', 'w') as f:
    
    f.write("***************************** \n")
    f.write("CWE_CHECKER VERSION RESULTS   \n")
    f.write("***************************** \n")

    for cur in range(size):
        bin_name = binaries[0][cur]
        f.write('\n')
        f.write(bin_name)
        f.write(": \n")

        for file in files:
            x = open(file)
            data = json.load(x)
            str_data = str(data[bin_name])
            
            f.write(str_data)
            f.write('\n')

f.close()