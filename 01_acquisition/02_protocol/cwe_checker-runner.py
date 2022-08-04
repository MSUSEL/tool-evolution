'''
- This file parses our outputs after running the cwe_checker tool with several binaries.

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

import utils
import os
import json

# directory with all binaries (660 for our tool-evolution)
file_path = "./01_acquisition/01_input/test_bins"
# file_path = "./01_acquisition/01_input/binaries"
files = os.listdir(file_path)

# write names of binary files to "binaries.json"
with open("./01_acquisition/04_product/binaries.json", 'w') as output_file:
    json.dump(files, output_file)

# initialize and generate program output
utils.initialize_output_generation(file_path, files)