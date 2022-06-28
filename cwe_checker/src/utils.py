'''
- This file details helpful functions to parse through data in the main.py file.

- To use this library: import utils
'''

from operator import mod
import os
import subprocess
import json
import time
from collections import Counter

statistics = {}
info_array = {}
releases = ["0.4", "0.5", "0.6"]  
# "0.2", "0.3", 
# "0.4", "0.5", "0.6"
UNABLE_TO_COUNT = -50


def generate_output(file_path):
    
    # begin with empty dictionary of statistics
    files = os.listdir(file_path)
    for filename in files:
        statistics[filename] = {}
        info_array[filename] = {}
        
    double_quotes = "\"\""
    num = 0
    
    for release_id in releases:
        
        for filename in files:
            
            print("Before running version ", release_id, " on file ", filename)
            
            # build commands
            base_command = "docker run --rm -v " + file_path + "\\" + filename
            
            if release_id == "0.5":
                modified_command = base_command + ":/input cwe_checker:0.5 /input"
                print("Command: ", modified_command)
            elif release_id == "0.4":
                modified_command = base_command + ":/tmp/input cwe_checker:0.4 cwe_checker /tmp/input"
                print("Command: ", modified_command)
            elif release_id == "stable":
                modified_command = base_command + ":/input fkiecad/cwe_checker:stable /input"
                print("Command: ", modified_command)
            elif release_id == "latest":
                modified_command = base_command + ":/input fkiecad/cwe_checker:latest /input"
                print("Command: ", modified_command)
            elif release_id == "0.3":
                modified_command = "bap " + file_path + " --pass=cwe-checker --cwe-checker-config=src/config.json"
                print("Command: ", modified_command)
            elif release_id == "0.6":
                modified_command = base_command + ":/input cwe_checker:0.6 /input"
                print("Command: ", modified_command)
                
            # store output to count vulnerabilities
            print("Running command on ", filename, " using version ", release_id, "... \n")
            output = subprocess.run(modified_command, shell=True, capture_output=True)
            
            print("After running command on ", filename, " using version ", release_id, "\n")
            print()
            print(str(output), "\n")
            print()
            
            output = str(output)
            
            try:
                num_vulnerabilities = count_vulnerabilities(release_id, output, filename)
                
                # print("Total number of vulnerabilities:", num_vulnerabilities, "\n")
            except:
                print("Exception Detected. \n")
                num_vulnerabilities = UNABLE_TO_COUNT
            
            # store number of vulnerabilities in statistics dictionary
            statistics[filename][release_id] = num_vulnerabilities
            
            print("Found %d vulnerabilities in %s using release %s" \
            % (num_vulnerabilities, filename, release_id), "\n\n")
            
    store_data(statistics)
    

def count_vulnerabilities(release_id, output, filename):
    
    total = 0
    
    if release_id == "0.5" or release_id == "0.6":
        print("Using version ", release_id, "\n")
        OSJ = count_scanner(output, "OS Command Injection")
        print("OSJ: ", OSJ)
        IROM = count_scanner(output, "Improper Restriction of Operations within the Bounds of a Memory Buffer")
        print("IROM:", IROM)
        BUOV = count_scanner(output, "Buffer Overflow")
        print("BUOV: ", BUOV)
        ECFS = count_scanner(output, "Use of Externally-Controlled Format String")
        print("ECFS: ", ECFS)
        IFWA = count_scanner(output, "Integer Overflow or Wraparound")
        print("IFWA: ", IFWA)
        IE = count_scanner(output, "Information Exposure Through Debug Information")
        print("IE: ", IE)
        CJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
        print("CJ: ", CJ)
        IEP = count_scanner(output, "Insufficient Entropy in PRNG")
        print("IEP: ", IEP)
        TOU = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
        print("TOU: ", TOU)
        DF = count_scanner(output, "Double Free")
        print("DF: ", DF)
        UAF = count_scanner(output, "Use After Free")
        print("UAF: ", UAF)
        USP = count_scanner(output, "Untrusted Search Path")
        print("USP: ", USP)
        SPT = count_scanner(output, "Use of sizeof() on a Pointer Type")
        print("SPT: ", SPT)
        NPD = count_scanner(output, "NULL Pointer Dereference")
        print("NPD: ", NPD)
        UMSK = count_scanner(output, "Use of umask() with chmod-style Argument")
        print("UMSK: ", UMSK)
        PDF = count_scanner(output,"Use of Potentially Dangerous Function")
        print("PDF: ", PDF)
        EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
        print("EXP: ", EXP)
        OOB = count_scanner(output, "Out-of-bounds Read")
        print("OOB: ", OOB)
        OOBW = count_scanner(output, "Out-of-bounds Write")
        print("OOBW: ", OOBW)
        
        total = OSJ + IROM + BUOV + ECFS + IFWA + IE + CJ + IEP + TOU + DF + UAF + USP + SPT + NPD + UMSK + PDF + EXP + OOB + OOBW
        info_array[filename][release_id] = "Total:", total, "[CWE-78] OS Command Injection:", OSJ, "[CWE-119] Improper Restriction of Operations within the Bounds of a Memory Buffer:", IROM, "[CWE-121] Buffer Overflow:", BUOV, "[CWE-134] Use of Externally-Controlled Format String:", ECFS, "[CWE-190] Integer Overflow or Wraparound:", IFWA, "[CWE-215] Information Exposure Through Debug Information:", IE, "[CWE-243] Creation of chroot Jail Without Changing Working Directory:", CJ, "[CWE-332] Insufficient Entropy in PRNG:", IEP, "[CWE-367] Time-of-check Time-of-use (TOCTOU) Race Condition:", TOU, "[CWE-415] Double Free:", DF, "[CWE-416] Use After Free:", UAF, "[CWE-426] Untrusted Search Path:", USP, "[CWE-467] Use of sizeof() on a Pointer Type:", SPT, "[CWE-467] NULL Pointer Dereference:", NPD, "[CWE-560] Use of umask() with chmod-style Argument:", UMSK, "[CWE-676] Use of Potentially Dangerous Function:", PDF, "[CWE-782] Exposed IOCTL with Insufficient Access Control:", EXP, "[CWE-125] Out-of-bounds Read:", OOB, "[CWE-787] Out-of-bounds Write:", OOBW
        
        return total
    
    elif release_id == "0.4" or release_id == "0.3" or release_id == "0.2":
        print("Using version 0.4 \n")
        OOB = count_scanner(output, "Out-of-bounds read")
        print("OOB: ", OOB)
        # OOBW = count_scanner(output, "Out-of-bounds Write")
        # print("OOBW: ", OOBW)
        IOW = count_scanner(output, "Integer Overflow or Wraparound")
        print("IOW: ", IOW)
        IE = count_scanner(output, "Information Exposure Through Debug Information")
        print("IE: ", IE)
        CCJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
        print("CCJ: ", CCJ)
        UE = count_scanner(output, "Uncaught Exception")
        print("UE: ", UE)
        IEP = count_scanner(output, "Insufficient Entropy in PRNG")
        print("IEP: ", IEP)
        TOCK = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
        print("TOCK: ", TOCK)
        DF = count_scanner(output, "Double Free")
        print("DF: ", DF)
        UAF = count_scanner(output, "Use After Free")
        print("UAF:", UAF)
        USP = count_scanner(output, "Untrusted Search Path")
        print("USP: ", USP)
        UUV = count_scanner(output, "Use of Uninitialized Variable")
        print("UUV: ", UUV)
        UOSO = count_scanner(output, "Use of sizeof() on a Pointer Type")
        print("UOSO: ", UOSO)
        NPD = count_scanner(output, "NULL Pointer Dereference")
        print("NPD: ", NPD)
        CSA = count_scanner(output, "Use of umask() with chmod-style Argument")
        print("CSA: ", CSA)
        PDF = count_scanner(output,"Use of Potentially Dangerous Function")
        print("PDF: ", PDF)
        EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
        print("EXP: ", EXP)
        
        total = OOB + IOW + IE + CCJ + UE + IEP + TOCK + DF + UAF + USP + UUV + UOSO + NPD + CSA + PDF + EXP
        info_array[filename][release_id] = "Total:", total, "[CWE-125] Out-of-bounds read:", OOB, "[CWE-190] Integer Overflow or Wraparound:", IOW, "[CWE-215] Information Exposure Through Debug Information:", IE, "[CWE-243] Creation of chroot Jail Without Changing Working Directory:", CCJ, "[CWE-248] Uncaught Exception:", UE, "[CWE-332] Insufficient Entropy in PRNG:", IEP, "[CWE-367] Time-of-check Time-of-use (TOCTOU) Race Condition:", TOCK, "[CWE-415] Double Free:", DF, "[CWE-416] Use After Free:", UAF, "[CWE-426] Untrusted Search Path:", USP, "[CWE-457] Use of Uninitialized Variable:", UUV, "[CWE-467] Use of sizeof() on a Pointer Type:", UOSO, "[CWE-476] NULL Pointer Dereference:", NPD, "[CWE-560] Use of umask() with chmod-style Argument:", CSA, "[CWE-676] Use of Potentially Dangerous Function:", PDF, "[CWE-782] Exposed IOCTL with Insufficient Access Control:", EXP
     
        return total
    

def count_scanner(output, vulnerability):
    
    # scan for key indicators of a vulnerability 
    # ([CWE###]...out of bounds)
    
    v_count = output.count(vulnerability)
    
    return v_count


def store_data(statistics):
    with open(r'C:\Users\clema\REU_2022\tool-evolution\cwe_checker\output_statistics\parsed_results' + '.json',
        'w', encoding='utf-8') as output_file: json.dump(statistics, output_file, ensure_ascii=False, indent=4)
    with open(r'C:\Users\clema\REU_2022\tool-evolution\cwe_checker\output_statistics\detailed_analysis' + '.txt',
        'w', encoding='utf-8') as output_file: json.dump(info_array, output_file, ensure_ascii=False, indent=4)
    # str(int(time.time())) 