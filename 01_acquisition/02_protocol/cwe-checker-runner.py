'''
- This file called utils.py which generates the cwe_checker output

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

import utils
import os

# Directory with all binaries
file_path = r"C:\Users\clema\REU_2022\benchmarks\binary"

files = os.listdir(file_path)

# write names of binary files to "binaries.json"
# with open('binaries.json', 'w') as output_file:
#     json.dump(files, output_file)

# Initialize and generate program output
utils.generate_output(file_path)