library(rjson)
library(dplyr)

# choose which results file to use (by unix time stamp of acquisition run time completion)
use_date <- 1658175857

# pull in results file
cve_bin <- fromJSON(file = sprintf("./01_acquisition/04_product/cve_bin_tool_results_%d.json", use_date)) %>%
  lapply(as.data.frame) %>%
  do.call(rbind, .) %>%
  # remove unwanted columns
  select(!X3.1)

# pull in release date data
version_dates <- read.csv("./02_wrangling/01_input/cve_bin_tool_release_dates.csv") %>%
    t()
dates <- as.Date(version_dates, format = "%m/%d/%y") %>% as.data.frame()
dates$version <- rownames(version_dates)
# structure of input file must be preserved for this code block to work
names(dates)[1] <- "date"

# make file names be a column
names(cve_bin) <- gsub("X", "version_", names(cve_bin))
cve_bin$filename <- rownames(cve_bin)

# go to long form
cve_bin_long <- cve_bin %>%
  pivot_longer(!filename, names_to="version", values_to="vuln_count")

# join to release dates
cve_bin_long <- left_join(cve_bin_long, dates)

# save as csv
sprintf("./02_wrangling/04_product/cve_bin_tool_wide_%d.csv", use_date) %>%
  write.csv(cve_bin, ., row.names = F)
sprintf("./02_wrangling/04_product/cve_bin_tool_long_%d.csv", use_date) %>%
  write.csv(cve_bin_long, ., row.names = F)
