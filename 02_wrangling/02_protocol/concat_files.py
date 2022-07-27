'''
This file concatenates multiples .json files into one parsed .txt file
'''

import json
import pandas as pd

versions = ["latest", "stable", "0.4", "0.5", "0.6"]
files = ["../../01_acquisition/04_product/cwe_checker_results-v_latest.json", "../../01_acquisition/04_product/cwe_checker_results-v_stable.json", "../../01_acquisition/04_product/cwe_checker_results-v0.4.json", "../../01_acquisition/04_product/cwe_checker_results-v0.5.json", "../../01_acquisition/04_product/cwe_checker_results-v0.6.json"]
binaries = pd.read_json("../../01_acquisition/01_input/binaries_list.json")
size = len(binaries)

with open("../../01_acquisition/04_product/cwe_checker_parsed_results.txt", 'w') as f:
    
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