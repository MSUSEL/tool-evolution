'''
This file details helpful functions to parse through data in the main.py file

To use this library: import utils
'''

import os
from collections import Counter

# def list_docker_images():
#     os.system('cmd /k "docker images"')

def navigate_to_dir(version):
    
    os.chdir("C:/Users/clema/REU_2022/benchmarks/output_version-0.5")
    
    
    
    # path = r'C:\Users\clema\REU_2022\benchmarks\output_version-0.5'
    
    # os.chdir(path)
    
    # os.system('cmd "cd C:\Users\clema\REU_2022\benchmarks\output_version-0.5"')
    
    # if version == 5:
    #     os.system('cd "C:\Users\clema\REU_2022\benchmarks\output_version-0.5"')
    # elif version == 4:
    #     os.system('cd "C:\Users\clema\REU_2022\benchmarks\output_version-0.4"')
    # elif version == 3:
    #     os.system('cd "C:\Users\clema\REU_2022\benchmarks\output_version-0.3"')
    # elif version == 2:
    #     os.system('cd "C:\Users\clema\REU_2022\benchmarks\output_version-0.2"')
        
    
# def generate_output_V5(file_path):
    
#     # establish path to files for reading
#     files = os.listdir(file_path)
#     double_quote = "\"\""
    
#     for filename in files:
#         base_command = r"cmd /k " + double_quote + "docker run --rm -v C:\Users\clema\REU_2022\benchmarks\binary"
#         modified_command = base_command + "\\" + filename + ":/input cwe_checker:0.5 /input " + ">" + filename + ".out"
#         # os.system('cmd /k "docker run --rm -v C:\Users\clema\REU_2022\binaries\3proxy:/input cwe_checker:0.5 /input')


def store_data(file_path):
    
    # establish path to output files
    # file_path = r"C:\Users\clema\REU_2022\benchmarks\output"
    files = os.listdir(file_path)
    total_data = ""
    
    # access each file in path
    for filename in files:
        
        # builds a new path to access next file
        new_file_path = file_path + "\\" + filename
        
        text_file = open(new_file_path, "r")
        data = text_file.read()
        text_file.close()
    
        total_data = total_data + data + "\n" 
         
    return total_data


def count_vulnerabilities(str, data):
    v_count = data.count(str)
    
    return v_count

    
def count_vulnerabilies_V5(data):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    vulnerability = '['
    v_count = count_vulnerabilities(vulnerability, data)
    
    return v_count
