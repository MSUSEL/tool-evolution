# this file should import all data needed to make all product and 
# incremental graphs

cve_bin <- read.csv("./02_wrangling/04_product/cve_bin_tool_wide_1658175857.csv")
cve_bin_long <- read.csv("./02_wrangling/04_product/cve_bin_tool_long_1658175857.csv")

cwe_checker <- read.csv("./03_analysis/01_input/cwe_checker_wide.csv")
cwe_checker_long <- read.csv("./03_analysis/01_input/cwe_checker_long.csv")

poster_theme <- function() {
  theme(
    text = element_text(size = 15, color = "#FFFFFF"),
    
    panel.background = element_rect(fill='#105397'),
    panel.grid = element_line(color='#031330'),
    
    plot.background = element_rect(fill='#105397'),
    
    axis.line = element_line(color='#031330'),
    axis.text.x = element_text(size = 10, color = "#FFFFFF"),
    
    legend.background = element_rect(fill="#105397"),
  )
}

save_recent_plot <- function(name) {
  ggsave(
    sprintf("%s.png", name), 
    bg     = '#105397', 
    path   = "./03_analysis/04_product/",
    height = 10,
    width  = 10,
    units  = "in"
  )
}
