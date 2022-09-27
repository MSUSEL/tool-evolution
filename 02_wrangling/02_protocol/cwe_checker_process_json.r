## Ann Marie here...working off of the results that Colleen produced on
## 09/26/2022 in an effort to summarize for the ICSE manuscript that is due next
## week

library(rjson)
library(tidyr)

# file name
filenm <- "cwe-checker-all-versions1664248617.json"
# file path
pth <- "../../01_acquisition/04_product/"
# the file
filenm <- paste0(pth, filenm)
rm(pth)

# check that file exists
file.exists(filenm)

# read in cwe-checker results
# pull in results file
cwe_check <- fromJSON(file = filenm) %>%
  lapply(as.data.frame) %>%
  do.call(rbind, .) %>%
  t()

# string that defines total number of findings in a binary
tot_find_str <- "TOTAL_FINDINGS"

# select only the rows that have the total findings string in their names
cwe_check <- cwe_check[grepl(tot_find_str, row.names(cwe_check)),]

# clean up the row names a bit
row.names(cwe_check) <- gsub(paste0(".",tot_find_str), "", row.names(cwe_check))
