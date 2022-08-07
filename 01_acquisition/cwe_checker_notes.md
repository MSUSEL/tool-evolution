# Cwe_checker Acquisition Notes
## 08/06/2022
### Thanks for reading! --Colleen

**Omitted Versions**
Versions `0.1`, `0.2`, and `0.3` of cwe_checker were dropped because they did not work on my device.  The 
`0.4`, `0.5`, and `0.6` versions use the Docker container to run, whereas `0.1`, `0.2`, and `0.3` need BAP 
and Rust (among other dependencies) to produce results.  I believe the main issue with these earlier releases 
are because these dependencies are not all backwards-compatible.  That is for example, if BAP needs version 
`1.6` but you have a later version like `2.2` installed, the program will not function as expected; I found 
it difficult to download a specific release of a dependency according to the cwe_checker Github README.md 
(https://github.com/fkie-cad/cwe_checker/blob/master/README.md).  Because of this extensive research and 
inability to execute the program, I decided to omit these versions.

**Docker Image Tags**
When I pulled the necessary Docker images to run cwe_checker, I tagged the images with their versions (0.4, 0.5, 0.6).
Feel free to tag the images differently, but note that the main driver code, utils.py, may not run as expected due to 
the changes needed in the way the Docker command is constructed.

**Method of Counting CWEs**
The number of findings in cwe_checker_breakdown.json is counted by scanning specifically for a "[CWE***]" label 
based on the list in list-of-cwes.json file (./01_acquisition/02_protocol/list-of-cwes.json).  Before this method, 
I would scan for a CWE's name, such as "Buffer Overflow"; however, the same CWE name may vary throughout versions, 
with the difference being in the capitalization of a letter (perhaps "buffer Overflow").  This could cause a CWE to 
be missed or mistakenly counted, so I modified the code to produce cwe_checker_breakdown.json which are more accurate 
results than previously produced results.

**Differences in CWE Scanning Between Versions**
In analyzing the results, it is important to take into the account which CWEs each version is acutally scanning for.
Certain CWEs show up in one README.md, and are omitted by developers in later versions.  To see a specific breakdown
of CWEs based on binaries through various versions, see previously mentioned file cwe_checker_breakdown.json
(./01_acquisition/04_product/cwe_checker_breakdown.json).
