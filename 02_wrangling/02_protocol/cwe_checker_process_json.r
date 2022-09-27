## Ann Marie here...working off of the results that Colleen produced on
## 09/26/2022 in an effort to summarize for the ICSE manuscript that is due next
## week

library(rjson)
library(tidyr)

# file name
filenm <- "cwe-checker-all-versions1664248617.json"
# run index
run_idx <- gsub(".*?([0-9]+).*", "\\1", filenm)
# file path for input data
pth <- "../../01_acquisition/04_product/"
# the results file to bring in and process
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

colnames(cwe_check) <- paste0("version_", colnames(cwe_check))

cwe_check <- as.data.frame(cwe_check)
cwe_check$filename <- row.names(cwe_check)

# create a df in long form
cwe_check_long <-
  cwe_check %>%
  pivot_longer(!filename, names_to="version", values_to="findings_count")

# write the data to csv
# specify the path where csv should be stored
pthout <- "../04_product"
# specify file names
widenm <- paste0("cwe_check_wide_", run_idx, ".csv")
longnm <- paste0("cwe_check_long_", run_idx, ".csv")
# write to file
write.csv(cwe_check, paste0("/", pthout, widenm), row.names = FALSE)
write.csv(cwe_check_long, paste0("/",pthout, longnm), row.names = FALSE)

