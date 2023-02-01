
# Setup -------------------------------------------------------------------
source("./tool-evolution/04_analysis/02_protocol/setup.R")
source("./tool-evolution/04_analysis/02_protocol/functions.R")

# Data Analysis -----------------------------------------------------------

# cwe_checker <- colSort(cwe_checker)
# cve_bin <- colSort(cve_bin)

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

cowplot::plot_grid(
  title_cwe,
  title_cve,

  cwe_finds_agg_by_ver_long %>% through_time_alpha(),
  cve_finds_agg_by_ver_long %>% through_time_alpha(),

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




# Descriptive stats -------------------------------------------------------


nrow(
  cwe_check_wide[
    apply(
      # use the numeric part of the df
      select(cwe_check_wide, !filename),
      # go through it by row (by binary)
      1,
      # check to see if the mean of the row is not identical to any of the values
      # in it...this tells us that the scores differed
      function(row_vec) any(row_vec != mean(row_vec))
    ),
  ]
)

nrow(
  cve_bin_wide[
    apply(
      # use the numeric part of the df
      select(cve_bin_wide, !filename),
      # go through it by row (by binary)
      1,
      # check to see if the mean of the row is not identical to any of the values
      # in it...this tells us that the scores differed
      function(row_vec) any(row_vec != mean(row_vec))
    ),
  ]
)

apply(cwe_interversion_change, 2, mean)
apply(cwe_interversion_change, 2, range)
apply(cwe_interversion_change, 2, sd)
apply(cwe_interversion_change, 2, median)


apply(cve_interversion_change, 2, mean)
apply(cve_interversion_change, 2, range)
apply(cve_interversion_change, 2, sd)
apply(cve_interversion_change, 2, median)





sankeyIt <- function(findings_dat_long, meth){
  if(meth == "sd") myLabels <- c("More than 2 SD of mean",
                                 "Between 1 and 2 SD of mean",
                                 "Within 1 SD of mean")
  if(meth == "jenks") myLabels <- c("High",
                                    "Medium",
                                    "Low")

  p <-
    ggplot(aes(x = sank_column, stratum = group, alluvium = filename,
               fill = group, label = group), data = findings_dat_long) +
    geom_flow(stat = "alluvium", lode.guidance = "frontback", alpha = 0.4) +
    geom_stratum() +
    theme(
      legend.position = "bottom",
      text = element_text(size = 12),
      axis.text = element_text(size = 10),
      axis.text.x = element_text(angle = 40, hjust=1)
    ) +
    # scale_fill_viridis_d(
    # option = "A",
    # scale_fill_brewer(
    #   palette = "GnBu",
    # direction = -1,
    scale_fill_manual(
      values = c("#660066", "#006666", "#666666"),
      labels = myLabels
    ) +
    guides(fill=guide_legend(title=NULL))+
    labs(x="", y= "Binary")
  p
}


# ggplot(aes(x = sank_column, stratum = group, alluvium = filename,
#            fill = group, label = group), data = cwe_groups_long) +
#   geom_flow(stat = "alluvium", lode.guidance = "frontback", alpha = 0.4) +
#   geom_stratum() +
#   theme(
#     legend.position = "bottom",
#     text = element_text(size = 12),
#     axis.text = element_text(size = 10),
#     axis.text.x = element_text(angle = 40, hjust=1)
#   ) +
#   # scale_fill_viridis_d(
#   # option = "A",
#   # scale_fill_brewer(
#   #   palette = "GnBu",
#   # direction = -1,
#   scale_fill_manual(
#     values = c("#660066", "#006666", "#666666"),
#     labels = c("More than 2 SD of mean",
#                "Between 1 and 2 SD of mean",
#                "Within 1 SD of mean")
#   ) +
#   guides(fill=guide_legend(title=NULL))+
#   labs(x="", y= "Binary")

sankeyIt(
  filter(
    cve_sd_groups_long,
    sank_column == "version_1.0"|
      sank_column == "version_2.0" |
      sank_column == "version_3.0"
  ),
  "sd"
)

sankeyIt(cve_sd_groups_long, "sd")
sankeyIt(cwe_sd_groups_long, "sd")

sankeyIt(cve_jenks_groups_long, "jenks")
sankeyIt(cwe_jenks_groups_long, "jenks")
sankeyIt(
  filter(
    cve_jenks_groups_long,
    sank_column == "version_1.0"|
      sank_column == "version_2.0" |
      sank_column == "version_3.0"
  ),
  "jenks"
)
