
# Setup -------------------------------------------------------------------
source("./tool-evolution/04_analysis/02_protocol/setup.R")
source("./tool-evolution/04_analysis/02_protocol/functions.R")

product_path <- "./tool-evolution/04_analysis/04_product/"

library(lmtest)
library(lme4)

# Data Analysis -----------------------------------------------------------

cwe_interversion_change <- calcInterVersionDiffs(cwe_finds_agg_by_ver_wide)
cve_interversion_change <- calcInterVersionDiffs(select(cve_finds_agg_by_ver_wide, filename, "1.0", "2.0", "3.0"))

cwe_jenks_bounds <- calcJenksBreaks(cwe_finds_agg_by_ver_long)
cve_jenks_bounds <- calcJenksBreaks(cve_finds_agg_by_ver_long)
cwe_jenks_groups <- groupBinariesWithinVersions(cwe_finds_agg_by_ver_wide, cwe_jenks_bounds, "jenks")
cve_jenks_groups <- groupBinariesWithinVersions(cve_finds_agg_by_ver_wide, cve_jenks_bounds, "jenks")
cwe_jenks_groups_long <- pivotGroupsDfLong(cwe_jenks_groups)
cve_jenks_groups_long <- pivotGroupsDfLong(cve_jenks_groups)


# Plots ------------------------------------------------------------------

title_cwe <- cowplot::ggdraw() + cowplot::draw_label("cwe-checker", fontface='bold', size = 11)
title_cve <- cowplot::ggdraw() + cowplot::draw_label("cve-bin-tool", fontface='bold', size = 11)

multipanel_ver_diffs <-
  cowplot::plot_grid(
    title_cwe,
    title_cve,

    cwe_finds_agg_by_ver_long %>% through_time_alpha(),
    cve_finds_agg_by_ver_long %>%
      filter(!(version %in% c("3.1", "3.1.2"))) %>%
      mutate(version = ifelse(version == "2.1.post1", "2.1.p1", version)) %>%
      through_time_alpha(),

    cwe_finds_agg_by_ver_long %>%
      calc_jenks_breaks(8) %>%
      sankey_jenks_cust(),
    cve_finds_agg_by_ver_long %>%
      filter(
        version == "1.0"| version == "2.0" | version == "3.0"
      ) %>%
      calc_jenks_breaks(8) %>%
      sankey_jenks_cust(),

    cwe_interversion_change %>%
      density_btw_vers(x_axis_labels = c("v0.4 - v0.5", "v0.5 - v0.6")),
    cve_interversion_change %>%
      density_btw_vers(x_axis_labels = c("v1.0 - v2.0", "v2.0 - v3.0")),

    nrow = 4,
    rel_heights = c(0.02, 0.18, 0.45, 0.35),
    labels = c("", "", LETTERS[1:6]),
    label_size = 11
  )

pdf(
  file = paste0(product_path, "multipanel_ver_diffs", ".pdf"),
  height = 8.25,
  width = 6)
multipanel_ver_diffs
dev.off()

# sankeyIt(cve_jenks_groups_long, "jenks")
# sankeyIt(cwe_jenks_groups_long, "jenks")
# sankeyIt(
#   filter(
#     cve_jenks_groups_long,
#     sank_column == "1.0"|
#       sank_column == "2.0" |
#       sank_column == "3.0"
#   ),
#   "jenks"
# )


# Descriptive stats -------------------------------------------------------

# This descriptive stats section is messy cutty-pastey...I have confirmed that
# the results here are correct, but this code is UGLY.

# What percentage of binaries had the same score for all versions of the cwe-checker?
nrow(
  cwe_finds_agg_by_ver_wide[
    apply(
      # use the numeric part of the df
      select(cwe_finds_agg_by_ver_wide, !filename),
      # go through it by row (by binary)
      1,
      # check to see if the row has multiple values
      function(row_vec) {
        row_vec %>%
          unique() %>%
          length() > 1
      }
    ),
  ]
)
100 * (1 -567/nrow(cwe_finds_agg_by_ver_wide) )

# which binaries have the same scores for all versions?
cwe_same_agg_scores <-
  cwe_finds_agg_by_ver_wide %>%
  column_to_rownames(var = "filename") %>%
  apply(1, function(x) length(unique(x))) %>%
  subset(. == 1) %>%
  names()
cwe_same_agg_scores

# print those scores
cwe_finds_agg_by_ver_wide %>%
  filter(filename %in% cwe_same_agg_scores) %>%
  column_to_rownames(var = "filename") %>%
  filter(rowSums(.) > 0 )

#  which binaries have zero results across all versions
cwe_all_zero_binaries <- cwe_same_agg_scores[!(cwe_same_agg_scores %in% c("dmesg", "pacat", "xfwm4-workspace-settings"))]
# test it...all should be zero
colSums(
  cwe_finds_agg_by_ver_wide[
    cwe_finds_agg_by_ver_wide$filename %in% cwe_all_zero_binaries,
    2:ncol(cwe_finds_agg_by_ver_wide)
  ]
)


# What percentage of binaries had the same score for all versions of the tools?
nrow(
  cve_finds_agg_by_ver_wide[
    apply(
      # use the numeric part of the df
      select(cve_finds_agg_by_ver_wide, -c(filename, "3.1", "3.1.2")),
      # go through it by row (by binary)
      1,
      # check to see if the row has multiple values
      function(row_vec) {
        row_vec %>%
          unique() %>%
          length() > 1
      }
      # function(row_vec) any(row_vec != mean(row_vec))
    ),
  ]
)
100 * (1 -645/nrow(cve_finds_agg_by_ver_wide) )

# which binaries have the same scores for the suite of versions we analyzed (omit 3.1 and 3.1.2)?
cve_same_agg_scores <-
  cve_finds_agg_by_ver_wide %>%
  column_to_rownames(var = "filename") %>%
  select(-c("3.1", "3.1.2")) %>%
  apply(1, function(x) length(unique(x))) %>%
  subset(. == 1) %>%
  names()
cve_same_agg_scores

# what are those scores?
cve_finds_agg_by_ver_wide %>%
  filter(filename %in% cve_same_agg_scores) %>%
  select(-c("3.1", "3.1.2")) %>%
  column_to_rownames(var = "filename") %>%
  filter(rowSums(.) > 0 )

cve_all_zero_binaries <- cve_same_agg_scores[!(cve_same_agg_scores %in% c("ag"))]
# test it...all should be zero
colSums(
  cve_finds_agg_by_ver_wide[
    cve_finds_agg_by_ver_wide$filename %in% cve_all_zero_binaries,
    2:ncol(cve_finds_agg_by_ver_wide)
  ]
)


# Some more descriptive stats that are in manuscript

apply(cwe_interversion_change, 2, mean)
apply(cwe_interversion_change, 2, range)
apply(cwe_interversion_change, 2, sd)
apply(cwe_interversion_change, 2, median)


apply(cve_interversion_change, 2, mean)
apply(cve_interversion_change, 2, range)
apply(cve_interversion_change, 2, sd)
apply(cve_interversion_change, 2, median)



# Inferential statistics --------------------------------------------------

# Use nonparametric statistics because I could only fit negative binomial
# regressions for cwe-checker. Negative binomial regressions for cve-bin-tool
# would not converge.  See below...

cwe_finds_agg_by_ver_long %>%
  friedman.test(findings_count ~ version | filename, data = .)
cve_finds_agg_by_ver_long %>%
  filter(!(version %in% c("3.1", "3.1.2"))) %>%
  friedman.test(findings_count ~ version | filename, data = .)
# "The median number of findings reported in binaries varied according to the
# version of the static analysis tool (CWE_Checker: Friedman chi-squared =
# 591.7, df = 2, p-value < 2.2e-16; CVE_Bin_Tool Friedman chi-squared = 4,715.5,
# df = 8, p-value < 2.2e-16).




# To run the negative binomial regressions, we need to get rid of rows where all
# of the findings are zero.  I also did a little work to link up the output data
# to include attributes...back when I thought that I would be able to fit the
# negative binomial regressions for both sets of data.  We may want to play with
# these data later so this workflow and these data are preserved here for
# posterity.

binary_attr <-
  read.csv("./tool-evolution/04_analysis/01_input/BinaryAttrs.csv") %>%
  tibble()

dim(binary_attr)

dim(binary_attr) # 652 binaries with attributes... but only 650 match up
sum(binary_attr$binary %in% cwe_finds_agg_by_ver_wide$filename)
sum(binary_attr$binary %in% cve_finds_agg_by_ver_wide$filename)

cwe_finds_agg_by_ver_long_attr <-
  binary_attr %>%
  left_join(
    cwe_finds_agg_by_ver_wide, ., by = c("filename" = "binary")
    ) %>%
  pivot_longer(!c(filename, size, compiler, static, domain), names_to = "version")

cve_finds_agg_by_ver_long_attr <-
  binary_attr %>%
  left_join(
    cve_finds_agg_by_ver_wide, ., by = c("filename" = "binary")
  ) %>%
  pivot_longer(!c(filename, size, compiler, static, domain), names_to = "version")


## Get rid of the all zero results and then see if version matters...Fit the
## data using a negative binomial regression...test for the effect of
## version...version matters!
cwe_ver <-
  cwe_finds_agg_by_ver_long_attr %>%
  filter(!(version %in% c("3.1", "3.1.2"))) %>%
  filter(!(filename %in% cwe_all_zero_binaries)) %>%
  glmer.nb(
    value ~ version + ( 1 | filename),
    data = .,
    control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=1e3))
  )
cwe_no_ver <-
  cwe_finds_agg_by_ver_long_attr %>%
  filter(!(version %in% c("3.1", "3.1.2"))) %>%
  filter(!(filename %in% cwe_all_zero_binaries)) %>%
  glmer.nb(
    value ~ 1 + ( 1 | filename),
    data = .,
    control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=1e3))
  )

anova(cwe_ver, cwe_no_ver)
lrtest(cwe_ver, cwe_no_ver)


### Tried everything that I know to make these negative binomial regressions fit
### for data from cve-bin-tool, but I can't do it.  The problem is that there
### are so many binaries with the exact same scores across the versions.
# cve_ver <-
#   cve_finds_agg_by_ver_long_attr %>%
#   filter(!(filename %in% cve_all_zero_binaries)) %>%
#   filter(!(version %in% c("0.1", "0.2", "0.3"))) %>%
#   glmer.nb(
#     value ~ version + ( 1 | filename),
#     data = .,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=1e3))
#   )
# cve_no_ver <-
#   cve_finds_agg_by_ver_long_attr %>%
#   filter(!(filename %in% cve_all_zero_binaries)) %>%
#   filter(!(version %in% c("0.1", "0.2", "0.3"))) %>%
#     glmer.nb(
#     value ~ 1 + ( 1 | filename),
#     data = .,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=1e3))
#   )

