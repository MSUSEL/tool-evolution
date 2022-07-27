library(tidyverse)
library(rjson)
library(ggplot2)

source("./03_analysis/01_input/import.r")

poster_theme <- function() {
  theme(
    panel.background = element_rect(fill='#105397'),
    panel.grid = element_line(color='#031330'),
    
    plot.background = element_rect(fill='#105397'),
    
    axis.line = element_line(color='#031330'),
    axis.text = element_text(color='#000000'),
    
    legend.background = element_rect(fill="#105397")
  )
}

cve_bin_long %>% ggplot(aes(x = date, y = vuln_count)) +
  geom_line(mapping = aes(group = filename), color="#D9F8D4", alpha=0.1, size=2) +
  ggtitle('cve-bin-tool Vulnerabilities per version') +
  poster_theme() +
  theme(axis.text.x = element_text(angle = 45, hjust=1))

cwe_checker_long %>% ggplot(aes(x = date, y = vuln_count)) +
  geom_line(mapping = aes(group = filename), color="#D9F8D4", alpha=0.1, size=2) +
  ggtitle('cwe_checker Vulnerabilities per version') +
  poster_theme() + 
  theme(axis.text.x = element_text(angle = 45, hjust=1))


ggsave(
  'cve_bin_alpha.png', 
  bg='#105397', 
  path="./03_analysis/04_product/",
  height="5in",
  width = "5in"
)
ggsave('cwe_checker_alpha.png', bg='#105397', path="./03_analysis/04_product/")
