cluster_plot <- function(d) {
  d %>% ggplot(mapping = aes(x = version, y = vuln_count))+
    geom_line(mapping = aes(group = filename, color = clusterIdx), alpha = 0.5, size = 1) +
    scale_x_discrete(guide = guide_axis(angle = 90)) +
    xlab("Version") + ylab("Findings Count") +
    facet_grid(cols = vars(clusterIdx)) +
    poster_theme() + 
    theme(
      legend.position = "none"
    ) +
    scale_fill_brewer(type = "qual", palette = "Greens")
}


# some plots
scores_long_withClusts %>%
  filter(toolName == "cve_bin_tool") %>%
  name_swaps() %>%
  cluster_plot() +
  theme(
    axis.text.x = element_text(size = 10)
  )
  

scores_long_withClusts %>%
  filter(toolName == "cwe_checker") %>%
  name_swaps() %>%
  cluster_plot()
