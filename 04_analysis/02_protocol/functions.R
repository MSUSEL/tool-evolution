######## functions used in protocol_plots_aggregated.R ########

# Convenience Functions --------------------------------------------------

# Sort and reorder columns based on their names
colSort <- function(df){df <- df[,order(colnames(df))]; return(df)}

# Deprecated.  Make row names from binary names and strip the df of the binary
# name column. Use tibble::rownames_to_column() instead.
makeRowNamesFromBinaryNames <-
  function(df, fileNameCol = "filename"){
    row.names(df) <- df[, fileNameCol] %>%
      unlist()
    df <- df[ , !(names(df) == fileNameCol)]
    return(df)
  }

# Deprecated.  Make a column in the df from row names (names of the binaries).
# Use tibble::rownames_to_column() instead.
makeBinaryNameColFromRowNms <-
  function(df, fileNameCol = "filename"){
    df[, fileNameCol] <- row.names(df)
    return(df)
  }


# Grouping Functions ------------------------------------------------------

# Calculate the mathematical difference in the number of findings reported by
# sequential versions of a static analysis tool.
calcInterVersionDiffs <-
  function(df, binaryFileNmCol = "filename"){
    # store the names
    binaryNames <- df[ , binaryFileNmCol] %>%
      unlist()
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

# Deprecated function.  Breaks findings data into 3 groups - groups with high,
# medium, and low numbers of findings based on deviation from the mean (1, 2,
# and 3 SD of the mean).
calcStdvBnds <- function(df){
  # df <- makeRowNamesFromBinaryNames(df)
  df <- column_to_rownames(df, var = "filename")

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

# Deprecated function.  Breaks findings data into exactly 3 groups - groups with
# high, medium, and low numbers of findings. Use calc_jenks_breaks instead.
calcJenksBreaks <- function(longDf, findings_col = 'findings_count'){
  breaks <- BAMMtools::getJenksBreaks(unlist(longDf[, findings_col]), k = 4)
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

# Calculate Jenks natural breaks for a set of findings
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

# Deprecated. Clunky function that groups the binaries based on whether they had
# "high", "medium", or "low" numbers of findings. Groups are calculated based on
# grouping method (either standard dev or Jenks natural breaks.)
groupBinariesWithinVersions <-
  function(df, boundsList, meth){

    # df <- makeRowNamesFromBinaryNames(df)
    df <- column_to_rownames(df, var = "filename")


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

# Basically a wrapper for pivoting from wide to long for a dataframe created by
# the function `groupBinariesWithinVersions`.
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

# Aggregate plotting functions --------------------------------------------


# Calculate jenks natural breaks for findings of a static analysis tool.  Plot
# the results (score groups across versions) in a sankey plot.
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

# Create a plot where the y-axis is scores for the binaries and the x-axis is
# version.  Each line represents an individual binary and is slightly
# transparent.
through_time_alpha <-
  function(d) {
    d %>%
      ggplot(aes(x = version, y = findings_count)) +
      geom_line(mapping = aes(group = filename), color="black", alpha=0.2, size=0.5) +
      labs(y = "Findings", x = "") +
      theme(
        axis.line = element_line(size = 0.65, color = "black", linetype = 1),
        axis.text.x = element_text(angle = 40, hjust=1),
        panel.grid.major = element_blank(),
        panel.grid.minor = element_blank(),
        panel.background = element_blank(),
        plot.margin = unit(c(7, 5, -12, 1), "pt")
      ) +
      scale_x_discrete(expand = expansion(c(0.01,0)))
  }

# Create symmetrical density plots of the changes between versions of the static
# analysis tools.
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
      geom_hline(yintercept = 0, linetype = 2, color = "black", size = 0.35) +
      geom_violin(
        scale = "area",
        width = 1.1,
        position=position_dodge(width = 0.5),
        size = 0.75
      )+
      labs(title = '') +
      scale_fill_manual( values = c("darkgrey", "darkgrey")) +
      theme(
        axis.line = element_line(size = 0.65, color = "black", linetype = 1),
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

# break up findings for the binaries into high, medium, and low scores grouping
# by either standard deviations or jenks natural breaks...and then plot the
# result
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
    scale_fill_manual(
      values = c("#660066", "#006666", "#666666"),
      labels = myLabels
    ) +
    guides(fill=guide_legend(title=NULL))+
    labs(x="", y= "Binary")
  p
}


######## functions used in protocol_plots_detailed.R ########

# Plot findings on y and version on x using a long df as the input
trendPlot <- function(long_df){
  ggplot(long_df,
         aes(x = version, y = value)) +
    facet_wrap( ~ Id, scales = "free_y") +
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

# Create a summary table based on a long data frame and statistic of choice
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

