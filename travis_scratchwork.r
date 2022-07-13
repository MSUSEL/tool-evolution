library(tidyverse)
library(rjson)
library(gplots)

# basic average plot
cve_bin_long %>% ggplot(aes(x = date, y=vuln_count)) +
    ggtitle("CVE bin tool (no v3.1, .1 alpha)") +
    geom_line(mapping = aes(group = filename), color="black", alpha=0.1, size=2)

# what are the average number of vulnerabilities for each version?
long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  stat_summary(fun = "mean", geom="point")

long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  ggtitle("cve bin tool jittered points") + 
  geom_jitter()

long_form %>% ggplot(aes(x = version, y=vuln_count)) +
  ggtitle("cve bin tool violins") + 
  geom_violin()

# time needs to be spanning the rows, and variables the columns
View(long_form)
View(cve_bin_dataframe)

colors = c(seq(-3,-2,length=100),seq(-2,0.5,length=100),seq(0.5,6,length=100))

my_palette <- colorRampPalette(c("white", "black"))(n = 299)

# heatmap with built in function 
# normalize each columns
cve_bin_dataframe %>% mutate_if(is.numeric, ~(scale(.) %>% as.vector)) %>%
  # sort by vulnerabilities in first version
  arrange(desc(version_3.1.1)) %>% 
  # remove filename column
  select(-starts_with("filename")) %>% 
  as.matrix() %>% 
  heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F, margin=c(10, 2))

