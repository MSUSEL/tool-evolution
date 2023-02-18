# Convenience Funcs -------------------------------------------------------


# convenience function for cwe checker
nestedlist_to_tibble <- function(nestedlist, list_name) {
  nestedlist %>%
    bind_rows %>%
    mutate(filename = names(nestedlist),
           version = list_name)
}

# summary table generator
smry_table <- function(long_df, f, orderByOutput){
  out <- as_tibble(
    with(
      long_df,
      tapply(value, list(Id, version), f)),
    rownames = NA
  )
  if(orderByOutput){ out <- arrange(out, apply(out, 1, max))}
  out  %>%
    rownames_to_column(var = "Id") %>%
    mutate(Id = factor(Id, levels = Id)) %>%
    pivot_longer(!Id, names_to = "version")
}
