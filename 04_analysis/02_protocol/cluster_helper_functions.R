poster_theme <- function() {
  theme(
    text = element_text(size = 17, color = "#FFFFFF"),
    
    panel.background = element_rect(fill='#105397'),
    panel.grid = element_line(color='#031330'),
    
    plot.background = element_rect(fill='#105397'),
    
    axis.line = element_line(color='#031330'),
    axis.text = element_text(size = 12, color = "#FFFFFF"),
    
    legend.background = element_rect(fill="#105397"),
    legend.key = element_rect(fill="#105397"),
    
    strip.background = element_rect(fill="#105397"),
  )
}

name_swaps <- function(d) {
  d %>% 
    mutate(
      "version" = str_replace(version, "version_", "")
    ) %>%
    mutate(
      "version" = str_replace(version, "post", "p")
    )
}
