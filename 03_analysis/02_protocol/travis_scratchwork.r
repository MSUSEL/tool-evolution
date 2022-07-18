library(networkD3)
library(reshape)
library(ggalluvial)
library(alluvial)
library(plyr); library(dplyr)

# heat map but normalized between zero and 1
cwe_checker %>% select(starts_with("version")) %>%
  apply(2, function(x) (x-min(x))/(max(x)-min(x))) %>%
  apply(2, as.numeric) %>%
  # sort by vulnerabilities in first version
  arrange(version_0.6) %>% 
  rev() %>%
  # remove filename column
  select(-starts_with("filename")) %>% 
  as.matrix() %>% 
  heatmap.2(Rowv = F, Colv = F, tracecol = NA, col=my_palette, labRow = F)


# Alluvial
break_diff <- 20

quants <- quantile(cwe_checker_long$vuln_count)

sankey_data <- cwe_checker %>% select(starts_with("version")) %>%
  apply(2, findInterval, quants) %>%
  apply(2, function(val) names(quants)[val]) %>%
  apply(2, table) %>%
  lapply(as.data.frame) %>% 
  imap(.x = ., ~ set_names(.x, c("vuln_count_bin", .y))) %>%
  reduce(full_join, by='vuln_count_bin') %>%
  replace(is.na(.), 0)

sankey_data$vuln_count_bin <- as.factor(sankey_data$vuln_count_bin)

sankey_long <- sankey_data %>% pivot_longer(!vuln_count_bin, names_to="version", values_to="count")

sankey_long$bin_version <- paste(sankey_long$version, sankey_long$vuln_count_bin, sep = " bin ")


ggallvm <- sankey_long %>% ggplot(aes(y = count, x = version, alluvium = vuln_count_bin))

ggallvm + geom_alluvium(aes(fill = vuln_count_bin, colour = vuln_count_bin),
                width = 1/4, alpha = 2/3, decreasing = FALSE)

?geom_alluvium

cve_bin_long$filename <- as.factor(cve_bin_long$file)

cve_bin_long %>% within(bin <- as.factor(floor(cve_bin_long$vuln_count / 50))) %>%
  ggplot(aes(x = version, stratum = bin, alluvium = filename,
             fill = bin, label = bin)) +
  scale_fill_brewer(type = "qual", palette = "Set2") +
  geom_flow(stat = "alluvium", lode.guidance = "frontback") +
  geom_stratum() +
  theme(legend.position = "bottom")


data(majors)
majors$curriculum <- as.factor(majors$curriculum)
ggplot(majors,
       aes(x = semester, stratum = curriculum, alluvium = student,
           fill = curriculum, label = curriculum)) +
  scale_fill_brewer(type = "qual", palette = "Set2") +
  geom_flow(stat = "alluvium", lode.guidance = "frontback",
            color = "darkgray") +
  geom_stratum() +
  theme(legend.position = "bottom") +
  ggtitle("student curricula across several semesters")
