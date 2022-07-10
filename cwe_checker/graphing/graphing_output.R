
library(rjson)
library(ggplot2)
library(tidyverse)

setwd("C:/Users/clema/REU_2022/tool-evolution/cwe_checker/output_statistics/version_results")

cwe_df <- fromJSON(file = "parsed_results.json") %>%
  lapply(as.data.frame) %>%
  do.call(rbind,.)

cwe_df$progNm <- row.names(cwe_df)
names(cwe_df) <- gsub('X', 'Version_', names(cwe_df))

version_dates <- data.frame(Version_0.6 = '2022-06-10', Version_0.5 = '2021-07-05', Version_0.4 = '2021-01-07') %>%
  t() %>%
  as.data.frame()

names(version_dates)[names(version_dates) == 'V1'] <- 'Date'
version_dates$Version <- row.names(version_dates)
as.Date(version_dates$Date)

pdf("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\box_plot.pdf")
my_box <- boxplot(cwe_df[,1:3])
dev.off()

cwe_df_long <- pivot_longer(cwe_df, !progNm, names_to = "Version", values_to = "vulCt") %>%
  left_join(version_dates)


p1 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = Version, y = vulCt))+
  geom_line(mapping = aes(group = progNm), color = 'black', alpha = 0.1, size = 2)+
  ggtitle('CWE_CHECKER Vulnerabilities per Version')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\vul_per_version.pdf")


p2 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = Version, y = vulCt))+
  stat_summary(fun = 'mean', geom = 'point')+
  ggtitle('CWE_CHECKER Version Means')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\version_means.pdf")


p3 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = Version, y = vulCt))+
  geom_violin()+
  stat_summary(fun = 'mean', geom = 'point')+
  ggtitle('CWE_CHECKER Violin Plot')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\violin_plot.pdf")


p4 <- 
  ggplot(data = cwe_df_long, mapping = aes(x = Version, y = vulCt))+
  geom_jitter()+
  ggtitle('CWE_CHECKER Jitter Plot')

ggsave("C:\\Users\\clema\\REU_2022\\tool-evolution\\cwe_checker\\graphing\\jitter_plot.pdf")



