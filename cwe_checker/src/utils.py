'''
- This file details helpful functions to parse through data in the main.py file.

- To use this library: import utils
'''

from cmath import exp
from itertools import count
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
    
    f = open("detailed_output.txt", 'w')
    f.write(
        '''
        OSJ = count_scanner(output, "OS Command Injection")
        BUOV = count_scanner(output, "Buffer Overflow")
        ECFS = count_scanner(output, "Use of Externally-Controlled Format String")
        IFWA = count_scanner(output, "Integer Overflow or Wraparound")
        IE = count_scanner(output, "Information Exposure Through Debug Information")
        CJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
        IEP = count_scanner(output, "Insufficient Entropy in PRNG")
        TOU = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
        DF = count_scanner(output, "Double Free")
        UAF = count_scanner(output, "Use After Free")
        USP = count_scanner(output, "Untrusted Search Path")
        SPT = count_scanner(output, "Use of sizeof() on a Pointer Type")
        NPD = count_scanner(output, "NULL Pointer Dereference")
        UMSK = count_scanner(output, "Use of umask() with chmod-style Argument")
        PDF = count_scanner(output,"Use of Potentially Dangerous Function")
        EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
        OOB = count_scanner(output, "may be out of bounds"))"
        
        '''
        )
    f.write("\n\n")
    
    for release_id in releases:
        
        for filename in files:
            
            print("Before running ", release_id, " on file ", filename, "\n")
            
            # build command for version 0.5
            base_command = "docker run --rm -v " + file_path + "\\" + filename + ":/input cwe_checker:0."
            
            if release_id == "0.5":
                modified_command = base_command + "5 /input"
                print("Command: ", modified_command, "\n")
            elif release_id == "0.4":
                modified_command = base_command + "4 /input"
                print("Command: ", modified_command, "\n")
    
            # store output to count vulnerabilities
            print("Going to run modified command \n")
            output = subprocess.run(modified_command, shell=True, capture_output=True)
            
            print("After running ", release_id, " on file ", filename, "\n")
            print()
            print(str(output), "\n")
            print()
            
            output = str(output)
            
            try:
                num_vulnerabilities, OSJ, BUOV, ECFS, IFWA, IE, CJ, IEP, TOU, DF, UAF, USP, SPT, NPD, UMSK, PDF, EXP, OOB = count_vulnerabilities(release_id, output)
                print("Total number of vulnerabilities:", num_vulnerabilities, "\n")
            except:
                print("Exception Detected. \n")
                num_vulnerabilities, OSJ, BUOV, ECFS, IFWA, IE, CJ, IEP, TOU, DF, UAF, USP, SPT, NPD, UMSK, PDF, EXP, OOB = UNABLE_TO_COUNT
            
            # store number of vulnerabilities in statistics dictionary
            statistics[filename][release_id] = num_vulnerabilities
            
            # write more detailed statistics to txt file
            f.write(str(filename))
            f.write(" version ")
            f.write(release_id)
            f.write("\n\n")
            
            f.write(str(OSJ))
            f.write("\n")
            f.write(str(BUOV))
            f.write("\n")
            f.write(str(ECFS))
            f.write("\n")
            f.write(str(IFWA))
            f.write("\n")
            f.write(str(IE))
            f.write("\n")
            f.write(str(CJ))
            f.write("\n")
            f.write(str(IEP))
            f.write("\n")
            f.write(str(TOU))
            f.write("\n")
            f.write(str(DF))
            f.write("\n")
            f.write(str(UAF))
            f.write("\n")
            f.write(str(USP))
            f.write("\n")
            f.write(str(SPT))
            f.write("\n")
            f.write(str(NPD))
            f.write("\n")
            f.write(str(UMSK))
            f.write("\n")
            f.write(str(PDF))
            f.write("\n")
            f.write(str(EXP))
            f.write("\n")
            f.write(str(OOB))
            
            f.write("\n\n")
            
            f.close()
            
            print("Found %d vulnerabilities in %s using release %s" \
            % (num_vulnerabilities, filename, release_id), "\n\n")
        
    store_data(statistics)


def store_data(statistics):
    with open(r'C:\Users\clema\REU_2022\tool-evolution\cwe_checker\output_statistics\cwe_checker_results' + str(int(time.time())) + '.json',
        'w', encoding='utf-8') as output_file: json.dump(statistics, output_file, ensure_ascii=False, indent=4)


def count_vulnerabilities(release_id, output):
    
    if release_id == "0.5":
        print("Using version 0.5 \n")
        num_vulnerabilities = count_scanner(output, '[')
        OSJ = count_scanner(output, "OS Command Injection")
        BUOV = count_scanner(output, "Buffer Overflow")
        ECFS = count_scanner(output, "Use of Externally-Controlled Format String")
        IFWA = count_scanner(output, "Integer Overflow or Wraparound")
        IE = count_scanner(output, "Information Exposure Through Debug Information")
        CJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
        IEP = count_scanner(output, "Insufficient Entropy in PRNG")
        TOU = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
        DF = count_scanner(output, "Double Free")
        UAF = count_scanner(output, "Use After Free")
        USP = count_scanner(output, "Untrusted Search Path")
        SPT = count_scanner(output, "Use of sizeof() on a Pointer Type")
        NPD = count_scanner(output, "NULL Pointer Dereference")
        UMSK = count_scanner(output, "Use of umask() with chmod-style Argument")
        PDF = count_scanner(output,"Use of Potentially Dangerous Function")
        EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
        OOB = count_scanner(output, "may be out of bounds")
        
        total = OSJ + BUOV + ECFS + IFWA + IE + CJ + IEP + TOU + DF + UAF + USP + SPT + NPD + UMSK + PDF + EXP + OOB
        
        return total, OSJ, BUOV, ECFS, IFWA, IE, CJ, IEP, TOU, DF, UAF, USP, SPT, NPD, UMSK, PDF, EXP, OOB
        
    elif release_id == "0.4":
        print("Using version 0.4 \n")
        return (count_vulnerabilies_V4(output, "out of bounds"))
    else:
        print("Version unknown \n")
        return 0
    

def count_scanner(output, vulnerability):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    v_count = output.count(vulnerability)
    
    return v_count


def count_vulnerabilies_V4(output, vulnerability):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    v_count = output.count(vulnerability)
    
    return v_count