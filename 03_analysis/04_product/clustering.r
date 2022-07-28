cluster_plot <- function(d) {
  d %>% ggplot(mapping = aes(x = version, y = vuln_count))+
    geom_line(mapping = aes(group = filename, color = cluster_title), alpha = 0.5, size = 1) +
    scale_x_discrete(guide = guide_axis(angle = 90)) +
    xlab("Version") + ylab("Vulnerability Count") +
    facet_grid(cols = vars(cluster_title)) +
    poster_theme() + 
    theme(
      legend.position = "none"
    )
}


# some plots
scores_long_withClusts %>%
  filter(toolName == "cve_bin_tool") %>%
  cluster_plot()
  

scores_long_withClusts %>%
  filter(toolName == "cwe_checker") %>%
  cluster_plot()
