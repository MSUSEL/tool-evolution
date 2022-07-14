cwe_checker %>% select(starts_with("version")) %>%
  apply(2, function(x) (x-min(x))/(max(x)-min(x))) %>% View()
  # sort by vulnerabilities in first version
  arrange(desc(version_0.6)) %>% 
  rev() %>%
  # remove filename column
  select(-starts_with("filename")) %>% 
  as.matrix() %>% 
  heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F)

  
cwe_checker$version_0.4 *2
