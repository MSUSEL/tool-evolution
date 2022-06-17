'''
- This file parses our outputs after running the cwe_checker tool with several binaries.

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

import utils
import os
import json

# Directory with all binaries
file_path = r"C:\Users\clema\REU_2022\benchmarks\binary"
# file_path = r"C:\Users\clema\REU_2022\benchmarks\binaryTest"
# file_path = r"/mnt/c/Users/clema/REU_2022/benchmarks/binaryTest"

files = os.listdir(file_path)

with open('binaries.json', 'w') as output_file:
    json.dump(files, output_file)

# Initialize and generate program output
# utils.generate_output(file_path)