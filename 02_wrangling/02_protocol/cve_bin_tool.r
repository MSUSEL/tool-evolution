cve_bin <- fromJSON(file = "../cve-bin-tool-runner/products/full_results_1655757361.json") %>% 
  lapply(as.data.frame) %>%
  do.call(rbind, .)

cve_bin <- cve_bin[, names(cve_bin)!="X3.1"]

read.csv("./02_wrangling/01_input/cve_bin_tool_release_dates.csv") %>% View()

names(version_dates) <- gsub("X", "version_", names(version_dates))
version_dates <- t(version_dates)
dates <- as.Date(version_dates, format = "%m-%d-%Y") %>% as.data.frame
dates$version <- rownames(version_dates)
names(dates)[1] <- "date"

# make file names be a column

names(cve_bin) <- gsub("X", "version_", names(cve_bin))
cve_bin$filename <- rownames(cve_bin)

# go to long form
cve_bin_long <- cve_bin %>% 
  pivot_longer(!filename, names_to="version", values_to="vuln_count")

cve_bin_long <- left_join(cve_bin_long, dates)