library(tidyverse)
library(ggplot2)


through_time_alpha <- function(d) {
  d %>% name_swaps() %>%
    ggplot(aes(x = version, y = vuln_count)) +
    geom_line(mapping = aes(group = filename), color="#D9F8D4", alpha=0.2, size=2) +
    poster_theme() +
    labs(y = "Findings Count", x = "Version") + 
    theme(
      axis.text.x = element_text(angle = 40, hjust=1)
    )
}

cve_bin_long %>% through_time_alpha()

cwe_checker_long %>% through_time_alpha()
  
