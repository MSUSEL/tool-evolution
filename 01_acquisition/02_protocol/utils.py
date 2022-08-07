'''
- This file details helpful functions to parse through data in the main.py file.

- To use this library: "import utils"
'''

import subprocess
import json
import time

releases = ["0.4", "0.5", "0.6"]  

ERROR_NOT_COUNTABLE = -9999


def initialize_output_generation(file_path, files): 
    cwe_breakdown = {
                     "0.4": {},
                     "0.5": {},
                     "0.6": {}
                    }
    # begin with empty dictionary of statistics
    for filename in files:
        for version in cwe_breakdown.keys():
            cwe_breakdown[version][filename] = {}
        
    # build version specific commands
    base_command = "docker run --rm -v " + file_path + "/"
    version_commands = {
        "version_0.4" : ":/tmp/input cwe_checker:0.4 cwe_checker /tmp/input",
        "version_0.5" : ":/input cwe_checker:0.5 /input",
        "version_0.6" : ":/input cwe_checker:0.6 /input"
    }
    run_files_through_versions(cwe_breakdown, files, base_command, version_commands)


def run_files_through_versions(cwe_breakdown, files, base_command, version_commands):
    
    for release_id in releases:
        
        for filename in files:
            # build command for given version and file
            modified_command = base_command + filename + version_commands["version_" + release_id]
            print("COMMAND: ", modified_command)
            print("Running command on ", filename, " using version ", release_id, "... \n")
            
            # store output to count findings
            output = subprocess.run(modified_command, shell=True, capture_output=True)
            output = str(output)
            
            print("After running command on ", filename, " using version ", release_id, "\n\n")
            print(str(output), "\n\n")
            
            # scan for CWEs and report an error if unable
            try:
                results = count_findings(cwe_breakdown, release_id, output, filename)
            except:
                print("Exception Detected. \n")
                results = ERROR_NOT_COUNTABLE
            
    store_data(cwe_breakdown)
    

def count_findings(cwe_breakdown, release_id, output, filename):
    # open .json file and make a dictionary from its CWE list
    cwe_list = open("./01_acquisition/02_protocol/list-of-cwes.json")
    cwe_dict = json.load(cwe_list)
    
    # initialize total findings key to 0
    for CWE in cwe_dict:
        cwe_breakdown[release_id][filename]["TOTAL_FINDINGS"] = 0
    
    print("*********START FINDINGS*********\n")
    
    # format and populate the cwe_breakdown dictionary
    for CWE in cwe_dict:
        cwe_breakdown[release_id][filename][CWE] = output.count(CWE)
        cwe_breakdown[release_id][filename]["TOTAL_FINDINGS"] += cwe_breakdown[release_id][filename][CWE]
    
    print(cwe_breakdown)
    
    print("\n*********END FINDINGS*********\n")
    
    cwe_list.close()
    
    return cwe_breakdown


def store_data(cwe_breakdown):
    # export breakdown of cwe count statistics for versions run above
    with open(r"./01_acquisition/04_product/cwe_checker_breakdown" + str(int(time.time())) + ".json",
        'w', encoding='utf-8') as output_file: json.dump(cwe_breakdown, output_file, ensure_ascii=False, indent=4)