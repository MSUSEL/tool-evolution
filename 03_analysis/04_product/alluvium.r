quants <- quantile(cwe_checker_long$vuln_count)

make_alluvium_graph <- function(d) {
  d %>% alluvated_table %>%
    within(vuln_count_bin <- as.factor(vuln_count_bin)) %>% 
    pivot_longer(!vuln_count_bin, 
                 names_to="version", values_to="count") %>% 
    ggplot(aes(y = count, x = version, alluvium = vuln_count_bin)) +
    geom_alluvium(aes(fill = vuln_count_bin, colour = vuln_count_bin),
                  width = 1/4, alpha = 2/3, decreasing = FALSE)
}

alluvated_table <- function(d) {
  d %>% apply(2, table) %>%
    lapply(as.data.frame) %>% 
    imap(.x = ., ~ set_names(.x, c("vuln_count_bin", .y))) %>%
    reduce(full_join, by='vuln_count_bin') %>%
    replace(is.na(.), 0)
}

cwe_checker %>% select(starts_with("version")) %>%
  apply(2, findInterval, quants) %>%
  apply(2, function(val) names(quants)[val]) %>%
  make_alluvium_graph()

cve_bin %>% select(starts_with("version")) %>%
  apply(2, function(c) floor(c/20)) %>%
  make_alluvium_graph()
