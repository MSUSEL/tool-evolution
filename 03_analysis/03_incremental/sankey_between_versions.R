library(networkD3)
library(reshape)
library(ggalluvial)
library(alluvial)
library(plyr); library(dplyr)

source("./03_analysis/01_input/import.r")

cve_bin_long$filename <- as.factor(cve_bin_long$file)

cve_bin_long %>% within(bin <- as.factor(floor(cve_bin_long$vuln_count / 50))) %>%
  ggplot(aes(x = version, stratum = bin, alluvium = filename,
             fill = bin, label = bin)) +
  scale_fill_brewer(type = "qual", palette = "Set2") +
  geom_flow(stat = "alluvium", lode.guidance = "frontback") +
  geom_stratum() +
  theme(legend.position = "bottom")

# Abandoned this graph because it is much less informative than expected