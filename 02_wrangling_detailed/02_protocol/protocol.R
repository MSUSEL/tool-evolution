
# Setup -------------------------------------------------------------------

library(rjson)
library(dplyr)
library(tibble)
library(purrr)
library(tidyr)
library(tidyselect)
library(stringr)


input_path <- "./tool-evolution/02_wrangling_detailed/01_input/"
protocol_path <- "./tool-evolution/02_wrangling_detailed/02_protocol/"

# Source necessary functions

protocol_path %>%
  paste0("functions.R") %>%
  source()

# Load input data from acquision 04_product folder into this 01_input folder. Be
# sure to set overwrite to **TRUE** only if you want to update the files in this
# directory for subsequent analyses.

"./tool-evolution/01_acquisition/04_product" %>%
  list.files(full.names = TRUE) %>%
  file.copy(
    from = .,
    to = input_path,
    overwrite = FALSE,
    recursive = TRUE,
    copy.mode = TRUE,
    copy.date = TRUE
  )

# Get the data

cwe_det_dat <- fromJSON(file = paste0(input_path,  "cwe_checker_breakdown.json"))
cve_det_dat <- fromJSON(file = paste0(input_path,  "cve_bin_tool_enumerated_1672822041.json"))

# Wrangling ---------------------------------------------------------------

##### CWE checker
cwe_det_dat <-
  cwe_det_dat %>%
  imap_dfr(nestedlist_to_tibble)

# run critical error check on cwe data
cwe_smry_dat <- select(cwe_det_dat, starts_with("[")) %>%
  rowSums()
identical(cwe_det_dat$TOTAL_FINDINGS, cwe_smry_dat)

# make a clean, long df
cwe_det_dat_long <-
  cwe_det_dat %>%
  select(c(starts_with("["), "filename", "version")) %>%
  pivot_longer(cols = starts_with("["), names_to = "Id")

cwe_det_dat_long <-
  mutate(cwe_det_dat_long, Id = gsub("[^0-9-]", "", cwe_det_dat_long$Id))


##### CVE Binary Tool

# vector with all versions of cve-bin-tool
cve_vers <- lapply(cve_det_dat, names) %>%
  unlist() %>%
  unique()
# vector of filenames
cve_filenames <- names(cve_det_dat)
# all combos of binary filenames and versions
cve_join_df <-
  expand_grid(
    filename = sort(cve_filenames),
    version = sort(cve_vers)
  )

# make a clean, long df from the list of lists
cve_det_dat_long <-
  cve_det_dat %>%
  # drop empty lists
  lapply(compact) %>%
  compact() %>%
  modify_depth(2, function(x) {
    x <-
      x %>%
      unlist(x) %>%
      as_tibble_col(column_name = "CVE")
    cve_column_crit <- substring(x$CVE, 1, 4) %in% c("CVE-", "UNKN")
    severity_column_crit <- substring(x$CVE, 1, 3) %in% c("LOW", "MED", "HIG", "CRI")
    severity_row_idx <- which(severity_column_crit)
    cve_rows_with_severities_idx <- severity_row_idx - 1 # always in position immediately before
    severities <- data.frame(x[cve_rows_with_severities_idx,], x[severity_row_idx,])
    names(severities) <- c("CVE", "Severity")
    CVEs <- x[cve_column_crit, ]
    x <- list(CVEs = CVEs, severities = severities)
    return(x)
      }
  )
cve_det_dat_long <-
  list(
    CVEs =
      lapply(cve_det_dat_long,
             function(sublist){
               sublist <- lapply(sublist, pluck, "CVEs")
               df_list <- lapply(
                 1:length(sublist),
                 function(i){
                   # add the version of the SAT to the df based on the named list
                   df <- mutate(sublist[[i]], version = names(sublist)[i]) %>%
                     # grab only columns where all data are populated
                     select(CVE, version)
                 }
               )
               # store results in one data frame for each program with findings
               df <- do.call(rbind, df_list)
             }
      ),
    severities =
      lapply(cve_det_dat_long,
             function(sublist){
               sublist <- lapply(sublist, pluck, "severities")
               do.call(rbind, sublist)
             }
      )
  )
severities <-
  pluck(cve_det_dat_long, "severities") %>%
  do.call(rbind, .) %>%
  distinct()
row.names(severities) <- NULL
severities$CVE_abbr <- substr(severities$CVE, 5, nchar(severities$CVE))

cve_det_dat_long <- pluck(cve_det_dat_long, "CVEs")

cve_det_dat_long <-
  lapply(
    1:length(cve_det_dat_long),
    function(i) {
      # get the right dataframe from the list
      df <- cve_det_dat_long[[i]]
      # create column in data frame with binary name (from list name)
      df <- mutate(df, filename = names(cve_det_dat_long)[i])
      return(df)
    }
  ) %>%
  do.call(rbind, .) %>%
  mutate(CVE = gsub("CVE-", "", .data$CVE))

cves_found <- unique(cve_det_dat_long$CVE)
cves_found[!(cves_found %in% substr(severities$CVE, 5, nchar(severities$CVE)) )]

# make cve-bin-tool data wide, add back the zero findings, and then make it long
# again...
cve_det_dat_wide <-
  cve_det_dat_long %>%
  mutate(cve_inst = 1) %>%
  group_by(filename, version, CVE)%>%
  summarise(cve_count = sum(cve_inst))%>%
  pivot_wider(
    id_cols = c(filename, version),
    names_from = CVE,
    values_from = cve_count,
    values_fill = 0
    ) %>%
  left_join(cve_join_df, .) %>%
  replace(is.na(.), 0)

# long df with cve data
cve_det_dat_long <-
  cve_det_dat_wide %>%
  pivot_longer(cols = !(c("filename", "version")), names_to = "Id")

# create an aggregated version based on the year that the cve was cataloged
cve_det_dat_long_agg <-
  cve_det_dat_long  %>%
  mutate(Id = substring(.data$Id, 1, 4)) %>%
  group_by(filename, version, Id)%>%
  summarise(value = sum(value))

# which versions of cve-bin-tool and binaries had "UNKNOWN" findings identifiers
unknowns <- cve_det_dat_long[(cve_det_dat_long$Id == "UNKNOWN" & cve_det_dat_long$value > 0),]
#write.csv(unknowns, "tool-evolution/01_acquisition/03_incremental/cves_tagged_unknown.csv", row.names = FALSE)

# Filtering ---------------------------------------------------------------

cve_vers_to_include <- c("1.0", "1.1", "2.0", "2.1", "2.1.post1", "2.2", "2.2.1", "3.0", "3.1.1")

cve_det_dat_long <-
  cve_det_dat_long[cve_det_dat_long$version %in% cve_vers_to_include ,]
cve_det_dat_long_agg <-
  cve_det_dat_long_agg[cve_det_dat_long_agg$version %in% cve_vers_to_include ,]
cve_det_dat_long <- left_join(cve_det_dat_long, severities, by = c("Id" = "CVE_abbr"))

# Basic descriptive stats -------------------------------------------------------------------

# First create some summary tables and then join them. These are hard coded; if
# you change the order, be sure to change the order of the column names.

join_cols <- c("Id", "version")
ordered_names <- c("Version","StdDev", "Median", "Mean", "Spread")
colsToName <- 2 : (length(ordered_names) + 1)

cve_smry <- smry_table(cve_det_dat_long_agg, sd, TRUE)
cve_smry_by_yr <-smry_table(cve_det_dat_long_agg, sd, FALSE)
cve_smry_by_yr_median <-smry_table(cve_det_dat_long_agg, median, FALSE)
cve_smry_by_yr_mean <-smry_table(cve_det_dat_long_agg, mean, FALSE)
cve_smry_by_yr_spread <-
  smry_table(
    cve_det_dat_long_agg,
    function(x) {100 * sum(x>0 )/ length(x)},
    FALSE
  )
cve_smry_by_yr <-
  cve_smry_by_yr %>%
  left_join(cve_smry_by_yr_median, by = join_cols) %>%
  left_join(cve_smry_by_yr_mean, by = join_cols) %>%
  left_join(cve_smry_by_yr_spread, by = join_cols)
names(cve_smry_by_yr)[colsToName] <- ordered_names


cwe_smry <- smry_table(cwe_det_dat_long, sd, TRUE)
cwe_smry_median <- smry_table(cwe_det_dat_long, median, TRUE)
cwe_smry_mean <- smry_table(cwe_det_dat_long, mean, TRUE)
cwe_smry_spread <-
  smry_table(
    cwe_det_dat_long,
    function(x) {100 * sum(x>0 )/ length(x)},
    TRUE
    )
cwe_smry <- cwe_smry %>%
  left_join(cwe_smry_median, by = join_cols) %>%
  left_join(cwe_smry_mean, by = join_cols) %>%
  left_join( cwe_smry_spread, by = join_cols)
names(cwe_smry)[colsToName] <- ordered_names

# Summary table for CVEs organized by severity
cve_det_dat_long$Severity[is.na(cve_det_dat_long$Severity)] <- "NOT REPORTED"
cve_det_dat_long$Severity <-
  factor(
    cve_det_dat_long$Severity,
    levels = c("CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT REPORTED")
  )

cve_det_dat_severSmry <-
  with(
    cve_det_dat_long,
    tapply(value, list(CVE, version), sd)
  ) %>%
  as.data.frame() %>%
  rownames_to_column(var = "CVE") %>%
  as_tibble() %>%
  mutate(CVE = factor(CVE, levels = CVE)) %>%
  pivot_longer(!CVE, names_to = "version") %>%
  left_join(severities, by = "CVE")

cve_det_dat_severSmry$Severity <-
  factor(
    cve_det_dat_severSmry$Severity,
    levels = c("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )

# Some quick summary stats...first how many of the really common binaries had at
# least one hit
vers_of_interest <- c("[CWE787]", "[CWE125]", "[CWE476]")
some_binary_counts_cwe <-
  mapply(
    function(ver, cwe_nm){
      with_detects <-
        sum(cwe_det_dat[cwe_nm][cwe_det_dat$version == ver,] >= 1)
      with_mult_detects <-
        sum(cwe_det_dat[cwe_nm][cwe_det_dat$version == ver,] > 1)
      return(
        list(
          cwe_nm = cwe_nm,
          version = ver,
          with_detects = with_detects,
          with_mult_detects = with_mult_detects)
        )
    },
    rep(unique(cwe_det_dat$version), each = length(vers_of_interest)),
    vers_of_interest,
    SIMPLIFY = FALSE,
    USE.NAMES = TRUE
  ) %>%
  do.call(cbind, .) %>%
  t() %>%
  data.frame(row.names = NULL) %>%
  arrange(unlist(cwe_nm))
some_binary_counts_cwe$pcnt_with_detects <- 100* unlist(some_binary_counts_cwe$with_detects) / length(unique(cwe_det_dat$filename))
some_binary_counts_cwe$pcnt_with_mult_detects <- 100* unlist(some_binary_counts_cwe$with_mult_detects) / length(unique(cwe_det_dat$filename))
some_binary_counts_cwe

# clean up environment
rm(colsToName, cve_join_df, cve_smry_by_yr_mean,
               cve_smry_by_yr_median, cve_smry_by_yr_spread, cve_vers, cve_vers_to_include,
               cves_found, cwe_smry_mean, cwe_smry_median, cwe_smry_spread, input_path, join_cols, nestedlist_to_tibble,
               ordered_names, protocol_path, smry_table, vers_of_interest)

# write RData image to file
save.image(file = "./tool-evolution/02_wrangling_detailed/04_product/detailed_data.RData")
