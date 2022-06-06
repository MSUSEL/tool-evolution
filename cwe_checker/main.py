'''
This file parses our outputs after running the cwe_checker tool with several binaries

Our goal is to count the number of vulnerabilities and weaknesses in the binary files, and compare this count with data 
recorded from other static analysis tools
'''

import utils

# hardcoded to test one file -- reports 70 vulnerabilities in 3proxy file

# VERSION CWE_CHECKER-0.5

# file_path = r"C:\Users\clema\REU_2022\benchmarks\output_version-0.5"
# data = utils.store_data(file_path)
# print(data)

# print()

# v = utils.count_vulnerabilies_V5(data)
# print(v)

# utils.list_docker_images()



# Navigate to correct output directory
utils.navigate_to_dir(5)



# Generate cwe_checker output for version 0.2, 0.3, 0.4, 0.5
