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

save_recent <- function(name, height=5, width=5) {
  ggsave(
    sprintf("%s.png", name), 
    bg     = '#105397', 
    path   = "./03_analysis/04_product/",
    height = height,
    width  = width,
    units  = "in"
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
