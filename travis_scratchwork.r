library(tidyverse)
library(rjson)
library(gplots)
library(maditr)

# basic average plot
cve_bin_long %>% ggplot(aes(x = date, y=vuln_count)) +
    ggtitle("CVE bin tool (no v3.1, .1 alpha)") +
    geom_line(mapping = aes(group = filename), color="black", alpha=0.1, size=2)

# what are the average number of vulnerabilities for each version?
cve_bin_long %>% ggplot(aes(x = version, y=vuln_count)) +
  stat_summary(fun = "mean", geom="point")

cve_bin_long %>% ggplot(aes(x = version, y=vuln_count)) +
  geom_jitter()

cwe_checker_long %>% ggplot(aes(x = version, y=vuln_count)) +
  geom_violin()


cwe_checker_long %>% within(is_zero <- vuln_count == 0) %>%
  ggplot(mapping = aes(x = version, y = reorder(filename, is_zero), fill = is_zero)) +
    geom_tile() +
    theme(
      axis.text.y=element_blank()
    ) +
    scale_fill_manual(values=c("FALSE"="firebrick", "TRUE"="dodgerblue"))

cwe_checker %>% select(starts_with("version")) %>%
  sapply(mean)

cve_bin %>% select(starts_with("version")) %>% 
  apply(2, function(c) c!=0) %>%
  apply(2, sum) %>% 
  tibble(version = names(.), not_zero = .) %>%
  ggplot(mapping = aes(x=version, y = not_zero)) +
    geom_bar(stat = 'identity')
