

# Setup -------------------------------------------------------------------

library(rjson)
library(tidyr)
library(dplyr)

# Import R Environment ----------------------------------------------------

# First: move product from detailed wrangling into input for aggregate
# wrangling. Do you want to overwrite the RData file in the input directory if
# it has already been created?
overwrite_value <- FALSE

file.copy(
  from = "./tool-evolution/02_wrangling_detailed/04_product/detailed_data.RData",
  to = "./tool-evolution/03_wrangling_aggregated/01_input/detailed_data.RData",
  overwrite = overwrite_value,
  copy.date = TRUE # preserve original file creation/modification date if possible
)

load(file = "./tool-evolution/03_wrangling_aggregated/01_input/detailed_data.RData")

# string that defines total number of findings in a binary
tot_find_str <- "TOTAL_FINDINGS"


# CWE Checker -------------------------------------------------------------

# long data frame that contains the findings aggregated by binary and
# static-analsis tool version
cwe_finds_agg_by_ver_long <-
  cwe_det_dat %>%
  select(all_of(tot_find_str), "filename", "version")
names(cwe_finds_agg_by_ver_long)[names(cwe_finds_agg_by_ver_long) == tot_find_str] <- "findings_count"

# wide data frame wherin rows are the binary and the columns are the sum of the
# findings in each static-analysis tool version
cwe_finds_agg_by_ver_wide <-
  cwe_finds_agg_by_ver_long %>%
  pivot_wider(
    id_cols = "filename",
    names_from = "version",
    values_from = "findings_count"
  )


# CVE Binary Tool ---------------------------------------------------------

# long data frame that contains the findings aggregated by binary and
# static-analsis tool version
cve_finds_agg_by_ver_long <-
  data.frame(
    filename = cve_det_dat_wide$filename,
    version = cve_det_dat_wide$version,
    findings_count =
      apply(
        cve_det_dat_wide[ , !( names(cve_det_dat_wide) %in% c("filename", "version") )],
        1,
        sum
      )
  ) %>%
  tibble()

# wide data frame wherin rows are the binary and the columns are the sum of the
# findings in each static-analysis tool version
cve_finds_agg_by_ver_wide <-
  cve_finds_agg_by_ver_long %>%
  pivot_wider(
    id_cols = "filename",
    names_from = "version",
    values_from = "findings_count"
  )


# Clean up enviro & write to product --------------------------------------

# clean up
rm(cve_filenames, cwe_smry_dat, overwrite_value, tot_find_str)

# write to product directory...
save.image("./tool-evolution/03_wrangling_aggregated/04_product/all_preprocessed_data.RData")
