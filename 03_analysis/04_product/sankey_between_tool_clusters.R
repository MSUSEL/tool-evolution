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
  pivot_longer(cols = !filename, names_to = "tool", values_to = "cluster")
  
pivoted_scores$cluster <- factor(pivoted_scores$cluster, levels=c("high", "medium", "low"))

pivoted_scores %>% ggplot(aes(x = tool, stratum = cluster, alluvium = filename,
             fill = cluster, label = cluster)) +
  scale_fill_brewer(type = "qual", palette = "Greens") +
  geom_flow(stat = "alluvium", lode.guidance = "frontback") +
  geom_stratum() +
  poster_theme() +
  theme(
    legend.position = "bottom",
    legend.background = element_rect(fill = "grey")
  ) +
  labs(x = "Tool")
