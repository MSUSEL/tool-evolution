'''
- This file details helpful functions to parse through data in the main.py file.

- To use this library: import utils
'''

import os
import subprocess
import json
import time
from collections import Counter

statistics = {}
releases = ["0.5"]  # "0.2", "0.3", "0.4"
UNABLE_TO_COUNT = -50

def initialize(file_path):
    
    # begin with empty dictionary of statistics
    files = os.listdir(file_path)
    for filename in files:
        statistics[filename] = {}


def generate_output(file_path):
    
    # establish path to files for reading
    files = os.listdir(file_path)
    double_quotes = "\"\""
    
    for release_id in releases:
        
        for filename in files:
            
            print("Before running ", release_id, " on file ", filename, "\n")
            
            # build command for version 0.5
            base_command = "docker run --rm -v " + file_path + "\\" + filename + ":/input cwe_checker:0."
            
            if release_id == "0.5":
                modified_command = base_command + "5 /input"
                print("Modified command: ", modified_command)
            elif release_id == "0.4":
                modified_command = base_command + "4 /input"
                print("Modified command: ", modified_command)
    
            # store output to count vulnerabilities
            print("\n Going to run modified command \n")
            output = subprocess.run(modified_command, shell=True, capture_output=True)
            
            print("After running ", release_id, " on file ", filename)
            print()
            print(str(output))
            
            output = str(output)
            
            
            try:
                num_vulnerabilities = count_vulnerabilities(release_id, output)
                print()
                print("Number of vul:", num_vulnerabilities)
                print()
                print()
            except:
                print("Exception Detected.")
                num_vulnerabilities = UNABLE_TO_COUNT
                
            statistics[filename][release_id] = num_vulnerabilities
    
            print("found %d vulnerabilities in %s using release %s" \
            % (num_vulnerabilities, filename, release_id))
        
    store_data(statistics)


def store_data(statistics):
    with open(r'C:\Users\clema\REU_2022\tool-evolution\cwe_checker\output_statistics\cwe_checker_results' + str(int(time.time())) + '.json',
        'w', encoding='utf-8') as output_file: json.dump(statistics, output_file, ensure_ascii=False, indent=4)


def count_vulnerabilities(release_id, output):
    
    if release_id == "0.5":
        print("\n It is version 0.5 \n")
        return(count_vulnerabilies_V5(output, "out of bounds"))
    elif release_id == "0.4":
        print("\n It is version 0.4 \n")
        return (count_vulnerabilies_V4(output, "out of bounds"))
    else:
        print("\n Version unknown \n")
        return 0
        


def count_vulnerabilies_V5(output, vulnerability):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    v_count = output.count(vulnerability)
    
    return v_count


def count_vulnerabilies_V4(output, vulnerability):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    v_count = output.count(vulnerability)
    
    return v_count