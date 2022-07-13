
library(rjson)
library(ggplot2)
library(tidyverse)

cwe_df <- fromJSON(file = "./cwe_checker/output_statistics/version_results/parsed_results.json") %>%
  lapply(as.data.frame) %>%
  do.call(rbind,.)

cwe_df$filename <- row.names(cwe_df)
names(cwe_df) <- gsub('X', 'version_', names(cwe_df))

version_dates <- data.frame(version_0.6 = '2022-06-10', version_0.5 = '2021-07-05', version_0.4 = '2021-01-07') %>%
  t() %>%
  as.data.frame()

names(version_dates)[names(version_dates) == 'V1'] <- 'date'
version_dates$version <- row.names(version_dates)
as.Date(version_dates$date)

cwe_df_long <- pivot_longer(cwe_df, !filename, names_to = "version", values_to = "vuln_count") %>%
  left_join(version_dates)


# (dear Travis)


pdf("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\box_plot.pdf")
my_box <- boxplot(cwe_df[,1:3])
dev.off()


p1 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
  geom_line(mapping = aes(group = filename), color = 'black', alpha = 0.1, size = 2)+
  ggtitle('CWE_CHECKER Vulnerabilities per version')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\vul_per_version.pdf")


p2 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
  stat_summary(fun = 'mean', geom = 'point')+
  ggtitle('CWE_CHECKER version Means')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\version_means.pdf")


p3 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
  geom_violin()+
  stat_summary(fun = 'mean', geom = 'point')+
  ggtitle('CWE_CHECKER Violin Plot')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\violin_plot.pdf")


p4 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
  geom_jitter()+
  ggtitle('CWE_CHECKER Jitter Plot')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\jitter_plot.pdf")



