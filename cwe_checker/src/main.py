'''
- This file parses our outputs after running the cwe_checker tool with several binaries.

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

import utils

# Directory with all binaries
# file_path = r"C:\Users\clema\REU_2022\benchmarks\binary"
file_path = r"C:\Users\clema\REU_2022\benchmarks\binaryTest"

# Initialize and generate program output
utils.initialize(file_path)
utils.generate_output(file_path)