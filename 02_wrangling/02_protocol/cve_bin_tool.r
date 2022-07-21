# choose which results file to use (by unix time stamp of acquisition run time completion)
use_date <- 1658175857

# pull in results file
cve_bin <- fromJSON(file = sprintf("./01_acquisition/04_product/cve_bin_tool_results_%d.json", use_date)) %>% 
  lapply(as.data.frame) %>%
  do.call(rbind, .)

# make file names be a column
cve_bin$filename <- rownames(cve_bin)

# rename columns
names(cve_bin) <- gsub("X", "version_", names(cve_bin))

# remove data about version 3.1
cve_bin <- cve_bin[, names(cve_bin)!="version_3.1"]

# pull in release date data
version_dates <- read.csv("./02_wrangling/01_input/cve_bin_tool_release_dates.csv") %>%
  t() %>% 
  as.data.frame() %>%
  within(date <- as.Date(V1, format="%m/%d/%y")) %>%
  rownames_to_column(var = "version") %>%
  select(-V1)

# go to long form
cve_bin_long <- cve_bin %>% 
  pivot_longer(!filename, names_to="version", values_to="vuln_count")

# join to release dates
cve_bin_long <- left_join(cve_bin_long, version_dates)

# save as csv
sprintf("./02_wrangling/04_product/cve_bin_tool_wide_%d.csv", use_date) %>%
  write.csv(cve_bin, ., row.names = F)
sprintf("./02_wrangling/04_product/cve_bin_tool_long_%d.csv", use_date) %>%
  write.csv(cve_bin_long, ., row.names = F)
