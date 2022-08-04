'''
- This file details helpful functions to parse through data in the main.py file.

- To use this library: import utils
'''
## We dropped versions 0.1, 0.2, and 0.3 because they weren't functional on my device.

from operator import mod
import os
import subprocess
import json
import time
from collections import Counter
from importlib_metadata import version

statistics = {}
info_array = {}
releases = ["0.4", "0.5", "0.6"]  

ERROR_NOT_COUNTABLE = -9999


def initialize_output_generation(file_path, files): 
    # begin with empty dictionary of statistics
    for filename in files:
        statistics[filename] = {}
        info_array[filename] = {}
    
    # build version specific commands
    base_command = "docker run --rm -v " + file_path + "\\"
    version_commands = {
        "version_0.4" : ":/tmp/input cwe_checker:0.4 cwe_checker /tmp/input",
        "version_0.5" : ":/input cwe_checker:0.5 /input",
        "version_0.6" : ":/input cwe_checker:0.6 /input"
    }
    run_files_through_versions(files, base_command, version_commands)


def run_files_through_versions(files, base_command, version_commands):
    
    for release_id in releases:
        
        for filename in files:
            # build command for given version and file
            modified_command = base_command + filename + version_commands["version_" + release_id]
            
            print("Running command on ", filename, " using version ", release_id, "... \n")
            
            # store output to count vulnerabilities
            output = subprocess.run(modified_command, shell=True, capture_output=True)
            output = str(output)
            
            print("After running command on ", filename, " using version ", release_id, "\n\n")
            print(str(output), "\n\n")
            
            # scan for vulnerabilities and report an error if unable
            try:
                num_vulnerabilities = count_vulnerabilities(release_id, output, filename)
            except:
                print("Exception Detected. \n")
                num_vulnerabilities = ERROR_NOT_COUNTABLE
            
            # store number of vulnerabilities in statistics dictionary
            statistics[filename][release_id] = num_vulnerabilities
            
            print("Found %d vulnerabilities in %s using release %s" \
            % (num_vulnerabilities, filename, release_id), "\n\n")
            
    store_data(statistics)
    

def count_vulnerabilities(release_id, output, filename):
    num_vulnerabilities = 0
    
    return num_vulnerabilities
    

def count_scanner(output, vulnerability): 
    # scan for key indicators of a vulnerability 
    v_count = output.count(vulnerability)
    
    return v_count


def store_data(statistics):
    # export vulnerability count statistics for versions run above
    with open(r"./01_acquisition/04_product/cwe_checker_parsed_results" + str(int(time.time())) + ".json",
        'w', encoding='utf-8') as output_file: json.dump(statistics, output_file, ensure_ascii=False, indent=4)
    
    




# # export the recorded CWE specific breakdown of output
    # with open(r"./01_acquisition/04_product/detailed_analysis" + str(int(time.time())) + ".txt",
    #     'w', encoding='utf-8') as output_file: json.dump(info_array, output_file, ensure_ascii=False, indent=4)    



# def count_vulnerabilities(release_id, output, filename):
    
#     total = 0
    
#     if release_id == "0.5" or release_id == "0.6":
#         print("Using version ", release_id, "\n")
#         OSJ = count_scanner(output, "OS Command Injection")
#         print("OSJ: ", OSJ)
#         IROM = count_scanner(output, "Improper Restriction of Operations within the Bounds of a Memory Buffer")
#         print("IROM:", IROM)
#         BUOV = count_scanner(output, "Buffer Overflow")
#         print("BUOV: ", BUOV)
#         ECFS = count_scanner(output, "Use of Externally-Controlled Format String")
#         print("ECFS: ", ECFS)
#         IFWA = count_scanner(output, "Integer Overflow or Wraparound")
#         print("IFWA: ", IFWA)
#         IE = count_scanner(output, "Information Exposure Through Debug Information")
#         print("IE: ", IE)
#         CJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
#         print("CJ: ", CJ)
#         IEP = count_scanner(output, "Insufficient Entropy in PRNG")
#         print("IEP: ", IEP)
#         TOU = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
#         print("TOU: ", TOU)
#         DF = count_scanner(output, "Double Free")
#         print("DF: ", DF)
#         UAF = count_scanner(output, "Use After Free")
#         print("UAF: ", UAF)
#         USP = count_scanner(output, "Untrusted Search Path")
#         print("USP: ", USP)
#         SPT = count_scanner(output, "Use of sizeof() on a Pointer Type")
#         print("SPT: ", SPT)
#         NPD = count_scanner(output, "NULL Pointer Dereference")
#         print("NPD: ", NPD)
#         UMSK = count_scanner(output, "Use of umask() with chmod-style Argument")
#         print("UMSK: ", UMSK)
#         PDF = count_scanner(output,"Use of Potentially Dangerous Function")
#         print("PDF: ", PDF)
#         EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
#         print("EXP: ", EXP)
#         OOB = count_scanner(output, "Out-of-bounds Read")
#         print("OOB: ", OOB)
#         OOBW = count_scanner(output, "Out-of-bounds Write")
#         print("OOBW: ", OOBW)
        
#         total = OSJ + IROM + BUOV + ECFS + IFWA + IE + CJ + IEP + TOU + DF + UAF + USP + SPT + NPD + UMSK + PDF + EXP + OOB + OOBW
#         info_array[filename][release_id] = "Total:", total, "[CWE-78] OS Command Injection:", OSJ, "[CWE-119] Improper Restriction of Operations within the Bounds of a Memory Buffer:", IROM, "[CWE-121] Buffer Overflow:", BUOV, "[CWE-134] Use of Externally-Controlled Format String:", ECFS, "[CWE-190] Integer Overflow or Wraparound:", IFWA, "[CWE-215] Information Exposure Through Debug Information:", IE, "[CWE-243] Creation of chroot Jail Without Changing Working Directory:", CJ, "[CWE-332] Insufficient Entropy in PRNG:", IEP, "[CWE-367] Time-of-check Time-of-use (TOCTOU) Race Condition:", TOU, "[CWE-415] Double Free:", DF, "[CWE-416] Use After Free:", UAF, "[CWE-426] Untrusted Search Path:", USP, "[CWE-467] Use of sizeof() on a Pointer Type:", SPT, "[CWE-467] NULL Pointer Dereference:", NPD, "[CWE-560] Use of umask() with chmod-style Argument:", UMSK, "[CWE-676] Use of Potentially Dangerous Function:", PDF, "[CWE-782] Exposed IOCTL with Insufficient Access Control:", EXP, "[CWE-125] Out-of-bounds Read:", OOB, "[CWE-787] Out-of-bounds Write:", OOBW
        
#         return total
    
#     elif release_id == "0.4" or release_id == "0.3" or release_id == "0.2":
#         print("Using version 0.4 \n")
#         OOB = count_scanner(output, "Out-of-bounds read")
#         print("OOB: ", OOB)
#         # OOBW = count_scanner(output, "Out-of-bounds Write")
#         # print("OOBW: ", OOBW)
#         IOW = count_scanner(output, "Integer Overflow or Wraparound")
#         print("IOW: ", IOW)
#         IE = count_scanner(output, "Information Exposure Through Debug Information")
#         print("IE: ", IE)
#         CCJ = count_scanner(output, "Creation of chroot Jail Without Changing Working Directory")
#         print("CCJ: ", CCJ)
#         UE = count_scanner(output, "Uncaught Exception")
#         print("UE: ", UE)
#         IEP = count_scanner(output, "Insufficient Entropy in PRNG")
#         print("IEP: ", IEP)
#         TOCK = count_scanner(output, "Time-of-check Time-of-use (TOCTOU) Race Condition")
#         print("TOCK: ", TOCK)
#         DF = count_scanner(output, "Double Free")
#         print("DF: ", DF)
#         UAF = count_scanner(output, "Use After Free")
#         print("UAF:", UAF)
#         USP = count_scanner(output, "Untrusted Search Path")
#         print("USP: ", USP)
#         UUV = count_scanner(output, "Use of Uninitialized Variable")
#         print("UUV: ", UUV)
#         UOSO = count_scanner(output, "Use of sizeof() on a Pointer Type")
#         print("UOSO: ", UOSO)
#         NPD = count_scanner(output, "NULL Pointer Dereference")
#         print("NPD: ", NPD)
#         CSA = count_scanner(output, "Use of umask() with chmod-style Argument")
#         print("CSA: ", CSA)
#         PDF = count_scanner(output,"Use of Potentially Dangerous Function")
#         print("PDF: ", PDF)
#         EXP = count_scanner(output,"Exposed IOCTL with Insufficient Access Control")
#         print("EXP: ", EXP)
        
#         total = OOB + IOW + IE + CCJ + UE + IEP + TOCK + DF + UAF + USP + UUV + UOSO + NPD + CSA + PDF + EXP
#         info_array[filename][release_id] = "Total:", total, "[CWE-125] Out-of-bounds read:", OOB, "[CWE-190] Integer Overflow or Wraparound:", IOW, "[CWE-215] Information Exposure Through Debug Information:", IE, "[CWE-243] Creation of chroot Jail Without Changing Working Directory:", CCJ, "[CWE-248] Uncaught Exception:", UE, "[CWE-332] Insufficient Entropy in PRNG:", IEP, "[CWE-367] Time-of-check Time-of-use (TOCTOU) Race Condition:", TOCK, "[CWE-415] Double Free:", DF, "[CWE-416] Use After Free:", UAF, "[CWE-426] Untrusted Search Path:", USP, "[CWE-457] Use of Uninitialized Variable:", UUV, "[CWE-467] Use of sizeof() on a Pointer Type:", UOSO, "[CWE-476] NULL Pointer Dereference:", NPD, "[CWE-560] Use of umask() with chmod-style Argument:", CSA, "[CWE-676] Use of Potentially Dangerous Function:", PDF, "[CWE-782] Exposed IOCTL with Insufficient Access Control:", EXP
     
#         return total
    
    
    
    
# def generate_output(file_path):
    
#     # begin with empty dictionary of statistics
#     files = os.listdir(file_path)
#     for filename in files:
#         statistics[filename] = {}
#         info_array[filename] = {}
             
#     # build commands
#     base_command = "docker run --rm -v " + file_path + "\\"

#     version_commands = {
#         "version_0.4" : ":/tmp/input cwe_checker:0.4 cwe_checker /tmp/input",
#         "version_0.5" : ":/input cwe_checker:0.5 /input",
#         "version_0.6" : ":/input cwe_checker:0.6 /input"
#     }
      
#     for release_id in releases:
        
#         for filename in files:
            
#             print("Before running version ", release_id, " on file ", filename)
            
#             modified_command = base_command + " " + filename + " " + version_commands["version_" + release_id]
            
#             # if release_id == "0.5":
#             #     modified_command = base_command + ":/input cwe_checker:0.5 /input"
#             #     print("Command: ", modified_command)
#             # elif release_id == "0.4":
#             #     modified_command = base_command + ":/tmp/input cwe_checker:0.4 cwe_checker /tmp/input"
#             #     print("Command: ", modified_command)
#             # elif release_id == "0.6":
#             #     modified_command = base_command + ":/input cwe_checker:0.6 /input"
#             #     print("Command: ", modified_command)
                
#             # store output to count vulnerabilities
#             print("Running command on ", filename, " using version ", release_id, "... \n")
#             output = subprocess.run(modified_command, shell=True, capture_output=True)
            
#             print("After running command on ", filename, " using version ", release_id, "\n\n")
#             print(str(output), "\n\n")
            
#             output = str(output)
            
#             try:
#                 num_vulnerabilities = count_vulnerabilities(release_id, output, filename)
                
#             except:
#                 print("Exception Detected. \n")
#                 num_vulnerabilities = UNABLE_TO_COUNT
            
#             # store number of vulnerabilities in statistics dictionary
#             statistics[filename][release_id] = num_vulnerabilities
            
#             print("Found %d vulnerabilities in %s using release %s" \
#             % (num_vulnerabilities, filename, release_id), "\n\n")
            
#     store_data(statistics)
    
