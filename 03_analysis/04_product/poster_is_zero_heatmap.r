is_zero_heatmap <- function(d) {
  d %>% within(is_zero <- vuln_count == 0) %>%
    ggplot(
      mapping = aes(x = date, y = reorder(filename, is_zero, decreasing = TRUE), 
                    fill = is_zero)) +
    geom_tile() +
    poster_theme() + 
    theme(
      axis.text.y=element_blank(),
      axis.text.x=element_text(angle = 40, hjust = 1),
      legend.key = element_rect(color = "black"),
      legend.position = "top"
    ) +
    labs(y = "files") +
    scale_fill_manual(name = "",
                      values=c("FALSE"="#E9F8E4", "TRUE"="#64BB63"),
                      labels = c("Greater than 0", "Equal to 0")
    )
}

cve_bin_long %>% is_zero_heatmap()

cwe_checker_long %>% is_zero_heatmap()
  
  

