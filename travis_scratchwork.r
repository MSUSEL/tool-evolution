library(tidyverse)
library(rjson)


# Give the input file name to the function.
cve_bin_raw <- fromJSON(file = "./cve-bin-tool-runner/data_outputs/full_results_1655757361.json") %>% 
  lapply(as.data.frame) %>%
  do.call(rbind, .)

cve_bin_raw <- cve_bin_raw[, names(cve_bin_raw)!="X3.1"]

version_dates <- data.frame(
  "3.1.1"="4-20-2022",
  "3.1"="4-19-2022",
  "3.0"="12-14-2021",
  "2.2.1"="8-4-2021",
  "2.2"="7-8-2021",
  "2.1.post1"="4-27-2021",
  "2.1"="12-7-2020",
  "2.0"="11-12-2020",
  "1.1"="10-15-2020",
  "1.0"="4-30-2020"
)
names(version_dates) <- gsub("X", "version_", names(version_dates))
version_dates <- t(version_dates)
dates <- as.Date(version_dates, format = "%m-%d-%Y") %>% as.data.frame
dates$version <- rownames(version_dates)
names(dates)[1] <- "date"

# make file names be a column

names(cve_bin_raw) <- gsub("X", "version_", names(cve_bin_raw))
cve_bin_dataframe <- cve_bin_raw
cve_bin_dataframe$filename <- rownames(cve_bin_dataframe)

# go to long form
long_form <- cve_bin_dataframe %>% 
  pivot_longer(!filename, names_to="version", values_to="vuln_count")

long_form <- left_join(long_form, dates)

## (dear colleen), DATA import done


# make plot
long_form %>% ggplot(aes(x = date, y=vuln_count)) +
    ggtitle("CVE bin tool (no v3.1, .1 alpha)") +
    geom_line(mapping = aes(group = file), color="black", alpha=0.1, size=2)

# what are the average number of vulnerabilities for each version?
long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  stat_summary(fun = "mean", geom="point")

long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  ggtitle("cve bin tool jittered points") + 
  geom_jitter()

long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  ggtitle("cve bin tool violins") + 
  geom_violin()


# Doing clustering
## time needs to be spanning the rows, and variables the columns
View(long_form)
View(cve_bin_dataframe)


  


