library(reshape)
library(ggalluvial)
library(alluvial)
library(plyr); library(dplyr)
library(stringi)

clusts_long <- scores_long_withClusts %>% select(all_of(c("filename", "toolName", "clusterIdx"))) %>%
  reshape(
    idvar = "filename", 
    timevar = "toolName", 
    direction = "wide"
  ) %>%
  pivot_longer(cols = !filename, names_to = "tool", values_to = "cluster")

clusts_long %>%
  ggplot(aes(x = tool, stratum = cluster, alluvium = filename,
             fill = cluster, label = cluster)) +
  scale_fill_brewer(type = "qual", palette = "Set2") +
  geom_flow(stat = "alluvium", lode.guidance = "frontback") +
  geom_stratum() +
  poster_theme() +
  theme(
    legend.position = "bottom",
    legend.background = element_rect(fill = "grey")
  )
