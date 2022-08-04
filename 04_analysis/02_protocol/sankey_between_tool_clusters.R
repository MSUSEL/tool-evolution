library(reshape)
library(ggalluvial)
library(alluvial)
library(plyr); library(dplyr)
library(stringi)

pivoted_scores <- scores_long_withClusts %>% select(all_of(c("filename", "toolName", "cluster_title"))) %>%
  reshape(
    idvar = "filename", 
    timevar = "toolName", 
    direction = "wide"
  ) %>%
  pivot_longer(cols = !filename, names_to = "tool", values_to = "cluster") %>%
  # advert your eyes, nothing else worked
  mutate(
    "tool" = replace(tool, tool == "cluster_title.cve_bin_tool", "cve_bin_tool")
  ) %>%
  mutate(
     "tool" = replace(tool, tool == "cluster_title.cwe_checker", "cwe_checker")
  )
  
# pivoted_scores$cluster <- factor(pivoted_scores$cluster, levels=c("high", "medium", "low"))

pivoted_scores %>% ggplot(aes(x = tool, stratum = cluster, alluvium = filename,
             fill = cluster, label = cluster)) +
  geom_flow(stat = "alluvium", lode.guidance = "frontback") +
  geom_stratum() +
  poster_theme() +
  theme(
    legend.position = "bottom",
    text = element_text(size = 18),
    axis.text = element_text(size = 15)
  ) +
  labs(x = "Tool")

