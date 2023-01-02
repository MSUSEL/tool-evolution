

# Setup -------------------------------------------------------------------
# setwd("/home/amr/Documents/Research/CyberQA/REU_2022/toolEvoAMR/tool-evolution")
# source("./04_analysis/01_input/setup.r")

### run toolEvo_versionEffects.R first...

library(dplyr)
library(tidyr)
library(ggplot2)
library(ggalluvial)

# Convenience Functions --------------------------------------------------

# reorder columns
colSort <- function(df){df <- df[,order(colnames(df))]; return(df)}

# make row names from binary names and strip the df of the binary name column
makeRowNamesFromBinaryNames <-
  function(df, fileNameCol = "filename"){
    row.names(df) <- df[, fileNameCol]
    df <- df[ , !(names(df) == fileNameCol)]
    return(df)
  }

# make a file name column from row names
makeBinaryNameColFromRowNms <-
  function(df, fileNameCol = "filename"){
    df[, fileNameCol] <- row.names(df)
    return(df)
  }


# Grouping Functions ------------------------------------------------------

calcInterVersionDiffs <-
  function(df, binaryFileNmCol = "filename"){
    # store the names
    binaryNames <- df[ , binaryFileNmCol]
    # remove the names from the df
    df <- df[ , !(names(df) == binaryFileNmCol)]
    # number of versions is the length of the names of the df
    numOfVersions <- length(names(df))
    # get the diffs
    out <-
      mapply(function(prevCol, currCol) {prevCol - currCol}, df[,1:(numOfVersions-1)], df[,2:numOfVersions]) %>%
      as.data.frame()
    # label the rows
    row.names(out) <- binaryNames
    # label the columns
    newColNames <-
      mapply(
        function(prevColNm, currColNm){
          paste0(prevColNm, "-", currColNm)
        },
        names(df)[1:(numOfVersions-1)],
        names(df)[2:numOfVersions]
      )
    names(out) <- newColNames
    return(out)
  }

# calculate standard deviation bounds

calcStdvBnds <- function(df){
  df <- makeRowNamesFromBinaryNames(df)

  # calc standard dev and mean for each version
  df_stdevs <- apply(df, 2, sd)
  df_means <- apply(df, 2, mean)

  # calc bounds for 1, 2, and 3 std devs of mean
  df_bounds <-
    list(
      low = list(
        lowerbound = -1*df_stdevs + df_means,
        upperbound = 1*df_stdevs + df_means),
      med = list(
        lowerbound = -2*df_stdevs + df_means,
        upperbound = 2*df_stdevs + df_means
      ),
      hi = list(
        lowerbound = -3*df_stdevs + df_means,
        upperbound = 3*df_stdevs + df_means
      )
    )
  return(df_bounds)
}

calcJenksBreaks <- function(longDf){
  breaks <- BAMMtools::getJenksBreaks(unlist(longDf[,'findings_count']), k= 4)
  df_bounds <-
    list(
      low = list(
        lowerbound = breaks[1],
        upperbound = breaks[2]-1
      ),
      med = list(
        lowerbound = breaks[2],
        upperbound = breaks[3]-1
      ),
      hi = list(
        lowerbound = breaks[3],
        upperbound = breaks[4]-1
      )
    )
  return(df_bounds)
}

calc_jenks_breaks <-
  function(longDf, ngroups){

    nbreaks <- ngroups + 1
    findings_vector <-
      longDf[,'findings_count'] %>%
      unlist()
    breaks <-
      findings_vector %>%
      BAMMtools::getJenksBreaks(k= nbreaks)

    breaks_list <-
      mapply(
        function(i, j) {
          lower <- ifelse(i == 1, min(breaks), breaks[i])
          upper <- ifelse(j == nbreaks, max(breaks), breaks[j]-1)
          c(lower, upper)
        },
        1:ngroups, 2:nbreaks,
        SIMPLIFY = FALSE
      )
    names(breaks_list) <- LETTERS[length(breaks_list):1]
    breaks_df <- do.call(rbind, breaks_list) %>%
      as.data.frame()
    names(breaks_df) <- c("lowerbound", "upperbound")

    out <-
      sapply(
        findings_vector,
        function(finding_score){
          grp <-
            row.names(breaks_df)[finding_score >= breaks_df$lowerbound &
                                   finding_score <= breaks_df$upperbound]
          return(grp)
        }
      )

    longDf$group <- factor(unlist(out))
    names(longDf)[names(longDf) == "version"] <- "sank_column"
    breaks_df$findings_range <-
      paste(breaks_df$lowerbound, breaks_df$upperbound, sep = " - ")
    breaks_df$group <- factor(row.names(breaks_df))
    longDf <- left_join(longDf, breaks_df, by = "group")
    return(longDf)
  }






groupBinariesWithinVersions <-
  function(df, boundsList, meth){

    df <- makeRowNamesFromBinaryNames(df)

    if(meth == "sd"){
      groupingsDf <-
        lapply(
          names(df),
          function(ver_name){
            # select column of scores for the version by name
            ver_dat <- df[ , ver_name]
            # assign values in "out" based on the standard dev of the version
            out <-
              ifelse(
                ver_dat < boundsList$med$lowerbound[ver_name] |
                  ver_dat > boundsList$med$upperbound[ver_name],
                "01_hi",
                ifelse(
                  ver_dat < boundsList$low$lowerbound[ver_name] |
                    ver_dat > boundsList$low$upperbound[ver_name],
                  "02_med",
                  "03_low"
                )
              )
            return(out)
          }
        ) %>%
        do.call(cbind, .) %>%
        as.data.frame()
    }

    if(meth == "jenks"){
      groupingsDf <-
        lapply(
          names(df),
          function(ver_name){
            # select column of scores for the version by name
            ver_dat <- df[ , ver_name]
            # assign values in "out" based on the standard dev of the version
            out <-
              ifelse(
                ver_dat < boundsList$med$lowerbound, "03_low",
                ifelse(ver_dat > boundsList$med$upperbound, "01_hi",
                       "02_med")
              )
            return(out)
          }
        ) %>%
        do.call(cbind, .) %>%
        as.data.frame()
    }

    # assign column and row names based on inputs
    names(groupingsDf)<- names(df)
    row.names(groupingsDf) <- row.names(df)
    return(groupingsDf)
  }

pivotGroupsDfLong <-
  function(groupingsDf){
    groupingsDf <- makeBinaryNameColFromRowNms(groupingsDf)
    out <-
      pivot_longer(
        groupingsDf,
        cols = !filename,
        names_to = "sank_column",
        values_to = "group"
      )
    return(out)
    }


# Data Analysis -----------------------------------------------------------

cwe_checker <- colSort(cwe_checker)
cve_bin <- colSort(cve_bin)

cwe_interversion_change <- calcInterVersionDiffs(cwe_check_wide)
cve_interversion_change <- calcInterVersionDiffs(select(cve_bin_wide, filename, v1.0,v2.0, v3.0))

cwe_sd_bounds <- calcStdvBnds(cwe_check_wide)
cve_sd_bounds <- calcStdvBnds(cve_bin_wide)
cwe_sd_groups <- groupBinariesWithinVersions(cwe_check_wide, cwe_sd_bounds, "sd")
cve_sd_groups <- groupBinariesWithinVersions(cve_bin_wide, cve_sd_bounds, "sd")
cwe_sd_groups_long <- pivotGroupsDfLong(cwe_sd_groups)
cve_sd_groups_long <- pivotGroupsDfLong(cve_sd_groups)

cwe_jenks_bounds <- calcJenksBreaks(cwe_check_long)
cve_jenks_bounds <- calcJenksBreaks(cve_bin_long)
cwe_jenks_groups <- groupBinariesWithinVersions(cwe_check_wide, cwe_jenks_bounds, "jenks")
cve_jenks_groups <- groupBinariesWithinVersions(cve_bin_wide, cve_jenks_bounds, "jenks")
cwe_jenks_groups_long <- pivotGroupsDfLong(cwe_jenks_groups)
cve_jenks_groups_long <- pivotGroupsDfLong(cve_jenks_groups)


# Plots! ------------------------------------------------------------------
sankey_jenks_cust <- function(findings_dat_long){

  #make pretty labels and put them in order (using some really ugly code)
  myLabels <-
    unique(findings_dat_long$findings_range)[
      order(unique(findings_dat_long$lowerbound))
    ] %>%
    rev()

  p <-
    ggplot(aes(x = sank_column, stratum = group, alluvium = filename,
               fill = group, label = group), data = findings_dat_long) +
    geom_flow(stat = "alluvium",
              lode.guidance = "frontback",
              alpha = 0.4) +
    geom_stratum() +
    theme(
      legend.position = "bottom",
      text = element_text(size = 12),
      axis.text = element_text(size = 8),
      axis.text.x = element_text(angle = 40, hjust=1),
      legend.title = element_text(size = 8),
      legend.text = element_text(size = 8),
      legend.margin = margin(t =-25),
      legend.key.size = unit(0.4, "cm"),
      panel.grid.major = element_blank(),
      panel.grid.minor = element_blank(),
      panel.background = element_blank(),
      plot.margin = unit(c(-5, 5, 0, 1), "pt")
    ) +
    scale_fill_viridis_d(
      labels = myLabels
      , direction = -1
      ) +
    guides(
      fill = guide_legend(
        # title="Findings Range",
        title = element_blank(),
        # title.position = "bottom",
        # title.hjust = 0.5,
        nrow =4,
        byrow = TRUE,
        reverse = TRUE
      )
    )+
    labs(x="", y= "Binary")+
    scale_x_discrete(expand = expansion(c(0,0)))
  p
}

through_time_alpha <-
  function(d) {
    d %>%
      # ggplot(aes(x = version, y = vuln_count)) +
      ggplot(aes(x = version, y = findings_count)) +
      geom_line(mapping = aes(group = filename), color="black", alpha=0.2, size=0.5) +
      labs(y = "Findings", x = "") +
      theme(
        axis.text.x = element_text(angle = 40, hjust=1),
        # axis.text.x=element_blank(),
        panel.grid.major = element_blank(),
        panel.grid.minor = element_blank(),
        panel.background = element_blank(),
        plot.margin = unit(c(7, 5, -12, 1), "pt")
      ) +
      scale_x_discrete(expand = expansion(c(0.01,0)))
  }

density_btw_vers <-
  function(df, myColumns = "all", x_axis_labels = NA){
    if(!("all" %in% myColumns)){
      df <- df[names(df) %in% myColumns]
    }

    df <-
      pivot_longer(df, everything(), names_to = "interver_chng")
    p <-
      ggplot(df, aes(x = interver_chng, y = value, fill =interver_chng)) +
      labs(y = expression(Delta*" Findings"), x = "") +
      geom_violin(
        scale = "area",
        width = 1.1,
        position=position_dodge(width = 0.5)
      )+
      labs(title = '') +
      scale_fill_manual( values = c("deeppink4", "deeppink4")) +
      theme(
        text = element_text(size = 12),
        axis.text = element_text(size = 8),
        axis.text.x = element_text(angle = 40, hjust = 1),
        panel.grid.major = element_blank(),
        panel.grid.minor = element_blank(),
        panel.background = element_blank(),
        legend.position = "none",
        plot.margin = unit(c(1.5, 2, -10, 1), "pt")
      )+
      scale_x_discrete(expand = expansion(c(0,0)), labels = x_axis_labels)
    p
  }
cowplot::plot_grid(
  density_btw_vers(
    cwe_interversion_change,
    x_axis_labels = c("v0.4 to v0.5", "v0.5 to v0.6")
  ),
  density_btw_vers(
    cve_interversion_change,
    x_axis_labels = c("v1.0 to v2.0", "v2.0 to v3.0")
  ),
  nrow =1
)

title_cwe <- cowplot::ggdraw() + cowplot::draw_label("cwe-checker", fontface='bold', size = 11)
title_cve <- cowplot::ggdraw() + cowplot::draw_label("cve-bin-tool", fontface='bold', size = 11)

cowplot::plot_grid(
  title_cwe,
  title_cve,

  cwe_check_long %>% through_time_alpha(),
  cve_bin_long %>% through_time_alpha(),

  sankey_jenks_cust(calc_jenks_breaks(cwe_check_long, 8)),
  sankey_jenks_cust(
    calc_jenks_breaks(
      filter(
        cve_bin_long,
        version == "v1.0"|
          version == "v2.0" |
          version == "v3.0"
      ), 8)),

  density_btw_vers(cwe_interversion_change, x_axis_labels = c("v0.4 - v0.5", "v0.5 - v0.6")),
  density_btw_vers(cve_interversion_change, x_axis_labels = c("v1.0 - v2.0", "v2.0 - v3.0")),

  nrow = 4,
  # rel_widths = c(3,3),
  rel_heights = c(0.02, 0.23, 0.52, 0.23),
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

apply(cve_interversion_change, 2, mean)
apply(cve_interversion_change, 2, range)
apply(cve_interversion_change, 2, sd)





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
