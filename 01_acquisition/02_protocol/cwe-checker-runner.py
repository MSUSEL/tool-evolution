'''
- This file parses our outputs after running the cwe_checker tool with several binaries.

- Our goal is to count the number of vulnerabilities in the binary files, and compare this data 
against other static analysis tools.
'''

import utils
import os
import json

# Directory with all binaries
file_path = "../01_input/binaries"
files = os.listdir(file_path)

# Initialize and generate program output
utils.generate_output(file_path)