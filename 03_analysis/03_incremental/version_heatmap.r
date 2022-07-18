library(plyr); library(dplyr)

# heat map but normalized between zero and 1
cwe_checker %>% apply_standardization() %>%
  rev() %>%
  arrange(version_0.6) %>%
  plot_as_heatmap()

cve_bin %>% apply_standardization() %>%
  arrange(version_3.1.1) %>%
  plot_as_heatmap()
  
  
apply_standardization <- function(d) {
  d %>% select(starts_with("version")) %>%
    apply(2, function(x) (x-min(x))/(max(x)-min(x))) %>%
    apply(2, as.numeric) %>%
    as_tibble()
}  

plot_as_heatmap <- function(d) {
  my_palette <- colorRampPalette(c("red", "black", "green"))(n = 299)
  
  d %>% select(-starts_with("filename")) %>% 
    as.matrix() %>% 
    heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F)
}
