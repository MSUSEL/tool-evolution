library(ggplot2)
library(dplyr)

binaryAttrs <- read.csv("./04_analysis/01_input/BinaryAttrs.csv") %>%
  dplyr::rename(filename = binary)

cve_bin_long_attr <- left_join(cve_bin_long, binaryAttrs)
cwe_checker_long_attr <- left_join(cwe_checker_long, binaryAttrs)

cve_bin_long_attr %>% ggplot(aes(x = version, y = vuln_count, size=size)) +
  geom_jitter() +
  theme(axis.text.x = element_text(angle = 15))

cwe_checker_long_attr %>% ggplot(aes(x = version, y = vuln_count, size=size)) +
  geom_jitter() +
  theme(axis.text.x = element_text(angle = 15))
