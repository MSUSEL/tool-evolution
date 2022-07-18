library(plyr); library(dplyr)

my_palette <- colorRampPalette(c("red", "black", "green"))(n = 299)

# heat map but normalized between zero and 1
cwe_checker %>% select(starts_with("version")) %>%
  apply(2, function(x) (x-min(x))/(max(x)-min(x))) %>%
  apply(2, as.numeric) %>%
  as_tibble() %>%
  # sort by vulnerabilities in first version
  arrange(version_0.6) %>%
  rev() %>%
  # remove filename column
  select(-starts_with("filename")) %>% 
  as.matrix() %>% 
  heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F)

cve_bin %>% select(starts_with("version")) %>%
  apply(2, function(x) (x-min(x))/(max(x)-min(x))) %>%
  apply(2, as.numeric) %>%
  as_tibble() %>%
  # sort by vulnerabilities in first version
  arrange(version_3.1.1) %>%
  rev() %>%
  # remove filename column
  select(-starts_with("filename")) %>% 
  as.matrix() %>% 
  heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F)
