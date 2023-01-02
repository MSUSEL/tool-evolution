library(tidyverse)
library(ggplot2)
library(gridExtra)


through_time_alpha <- function(d) {
  d %>%
    # ggplot(aes(x = version, y = vuln_count)) +
    ggplot(aes(x = version, y = findings_count)) +
    geom_line(mapping = aes(group = filename), color="black", alpha=0.2, size=0.5) +
    labs(y = "Findings Count", x = "Version") +
    theme(
      axis.text.x = element_text(angle = 40, hjust=1)
    )
}

grid.arrange(
  cve_bin_long %>% through_time_alpha(),
  cwe_checker_long %>% through_time_alpha(),
  nrow = 2
)



