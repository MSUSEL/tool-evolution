
library(rjson)
library(ggplot2)
library(tidyverse)

cwe_checker <- fromJSON(file = "./cwe_checker/output_statistics/version_results/parsed_results.json") %>%
  lapply(as.data.frame) %>%
  do.call(rbind,.)

cwe_checker$filename <- row.names(cwe_checker)
names(cwe_checker) <- gsub('X', 'version_', names(cwe_checker))
version_dates <- data.frame(version_0.6 = '2022-06-10', version_0.5 = '2021-07-05', version_0.4 = '2021-01-07') %>%
  t() %>%
  as.data.frame()

names(version_dates)[names(version_dates) == 'V1'] <- 'date'

version_dates$version <- row.names(version_dates)

as.Date(version_dates$date)

cwe_checker_long <- pivot_longer(cwe_checker, !filename, names_to = "version", values_to = "vuln_count") %>%
  left_join(version_dates)



cve_bin <- fromJSON(file = "./cve-bin-tool-runner/data_outputs/full_results_1655757361.json") %>% 
  lapply(as.data.frame) %>%
  do.call(rbind, .)
cve_bin <- cve_bin[, names(cve_bin)!="X3.1"]
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
names(cve_bin) <- gsub("X", "version_", names(cve_bin))
cve_bin$filename <- rownames(cve_bin)
# go to long form
cve_bin_long <- cve_bin %>% 
  pivot_longer(!filename, names_to="version", values_to="vuln_count")
cve_bin_long <- left_join(cve_bin_long, dates)






# 
# pdf("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\box_plot.pdf")
# my_box <- boxplot(cwe_df[,1:3])
# dev.off()
# 
# 
# p1 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_line(mapping = aes(group = filename), color = 'black', alpha = 0.1, size = 2)+
#   ggtitle('CWE_CHECKER Vulnerabilities per version')
# 
# ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\vul_per_version.pdf")
# 
# 
# p2 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   stat_summary(fun = 'mean', geom = 'point')+
#   ggtitle('CWE_CHECKER version Means')
# 
# ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\version_means.pdf")
# 
# 
# p3 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_violin()+
#   stat_summary(fun = 'mean', geom = 'point')+
#   ggtitle('CWE_CHECKER Violin Plot')
# 
# ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\violin_plot.pdf")
# 
# 
# p4 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_jitter()+
#   ggtitle('CWE_CHECKER Jitter Plot')
# 
# ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\jitter_plot.pdf")
# 
# 

