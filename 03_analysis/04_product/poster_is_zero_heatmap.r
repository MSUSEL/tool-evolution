is_zero_heatmap <- function(d) {
  d %>% within(is_zero <- vuln_count == 0) %>%
    ggplot(
      mapping = aes(x = version, y = reorder(filename, is_zero, decreasing = TRUE), 
                    fill = is_zero)) +
    geom_tile() +
    poster_theme() + 
    theme(
      axis.text.y=element_blank(),
      axis.text.x=element_text(angle = 40, hjust = 1),
      axis.title.y=element_text(angle = 0, vjust = .5),
      legend.key = element_rect(color = "black"),
      legend.position = "top"
    ) +
    labs(y = "Files", x = "Date") +
    scale_fill_manual(name = "",
                      values=c("FALSE"="#E9F8E4", "TRUE"="#64BB63"),
                      labels = c("At Least 1 Vulnerability", "No Vulnerabilities")
    )
}

cve_bin_long %>% is_zero_heatmap()
cwe_checker_long %>% is_zero_heatmap()
  
  

