'''
- This file called utils.py which generates the cwe_checker output

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

from pytest import ExitCode
import utils
import os
import json

# directory with all binaries
# file_path = "./01_acquisition/01_input/binaries"
file_path = "./01_acquisition/01_input/test_bins"
files = os.listdir(file_path)

# write names of binary files to "binaries.json"
with open('./01_acquisition/04_product/binaries.json', 'w') as output_file:
    json.dump(files, output_file)

# write txt file to json
with open('./01_acquisition/02_protocol/list-of-cwes.txt', 'r') as f:
    txt_output = f.readlines()

with open('./01_acquisition/02_protocol/list-of-cwes.json', 'w') as output_file:
    json.dump(txt_output, output_file)

# Initialize and generate program output
utils.initialize_output_generation(file_path, files)