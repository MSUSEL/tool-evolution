
# Setup -------------------------------------------------------------------

library(rjson)
library(dplyr)
library(tibble)
library(purrr)
library(tidyr)
library(ggplot2)
library(tidyselect)
library(egg)
library(stringr)
library(RColorBrewer)

cwe_rel_path <- "tool-evolution/01_acquisition/04_product/"
cve_rel_path <- "tool-evolution/01_acquisition/03_incremental/"
cwe_det_dat <- fromJSON(file = paste0(cwe_rel_path,  "cwe_checker_breakdown.json"))
cve_det_dat <- fromJSON(file = paste0(cve_rel_path,  "cve_bin_tool_enumerated_1672822041.json"))

# cve_complete <- read.csv("/home/amr/Documents/Research/CyberQA/REU_2022/CVE_List/allitems.csv")


# Convenience Funcs -------------------------------------------------------


# convenience function for cwe checker
nestedlist_to_tibble <- function(nestedlist, list_name) {
  nestedlist %>%
    bind_rows %>%
    mutate(filename = names(nestedlist),
           version = list_name)
}



# Wrangling ---------------------------------------------------------------

##### CWE checker
cwe_det_dat <-
  cwe_det_dat %>%
  imap_dfr(nestedlist_to_tibble)

# run critical error check on cwe data
cwe_smry_dat <- select(cwe_det_dat, starts_with("[")) %>%
  rowSums()
identical(cwe_det_dat$TOTAL_FINDINGS, cwe_smry_dat)

cwe_det_dat_long <-
  cwe_det_dat %>%
  select(c(starts_with("["), "filename", "version")) %>%
  pivot_longer(cols = starts_with("["), names_to = "Id") %>%
  mutate(Id = gsub("[^0-9-]", "", .data$Id))


##### CVE Binary Tool

cve_det_dat_df_nms <-
  c("vendor", "product", "ver", "CVE")

cve_vers <- lapply(cve_det_dat, names) %>%
  unlist() %>%
  unique()
cve_filenames <- names(cve_det_dat)
# all combos of binary filenames and versions
cve_join_df <-
  expand_grid(
    filename = sort(cve_filenames),
    version = sort(cve_vers)
  )

cve_det_dat_long <-
  cve_det_dat %>%
  # drop empty lists
  lapply(compact) %>%
  compact() %>%
  modify_depth(2, function(x) {
    # names(x)[1:4] <- cve_det_dat_df_nms
    # x <-
    #   x %>%
    #   as.data.frame()%>%
    #   t() %>%
    #   data.frame()
    #
    # x <- x[,1:4]
    #
    # colnames(x) <- cve_det_dat_df_nms
    # x <- as_tibble(x)
    # return(x)
    # class(x)
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

cve_det_dat_long <-
  cve_det_dat_wide %>%
  pivot_longer(cols = !(c("filename", "version")), names_to = "Id")

cve_det_dat_long_agg <-
  cve_det_dat_long  %>%
  mutate(Id = substring(.data$Id, 1, 4)) %>%
  group_by(filename, version, Id)%>%
  summarise(value = sum(value))



unknowns <- cve_det_dat_long[(cve_det_dat_long$Id == "UNKNOWN" & cve_det_dat_long$value > 0),]
#write.csv(unknowns, "tool-evolution/01_acquisition/03_incremental/cves_tagged_unknown.csv", row.names = FALSE)
# Filtering ---------------------------------------------------------------

cve_det_dat_long <- cve_det_dat_long[cve_det_dat_long$version != "3.1.2",]
cve_det_dat_long_agg <- cve_det_dat_long_agg[cve_det_dat_long_agg$version != "3.1.2",]

cve_det_dat_long <- left_join(cve_det_dat_long, severities, by = c("Id" = "CVE_abbr"))

# Plots -------------------------------------------------------------------

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

cve_smry <- smry_table(cve_det_dat_long_agg, sd, TRUE)

cve_smry_by_yr <-smry_table(cve_det_dat_long_agg, sd, FALSE)
cve_smry_by_yr_median <-smry_table(cve_det_dat_long_agg, median, FALSE)
cve_smry_by_yr_mean <-smry_table(cve_det_dat_long_agg, mean, FALSE)
cve_smry_by_yr <- left_join(cve_smry_by_yr, cve_smry_by_yr_median, by = c("Id", "version"))
cve_smry_by_yr <- left_join(cve_smry_by_yr, cve_smry_by_yr_mean, by = c("Id", "version"))
names(cve_smry_by_yr)[2:5] <- c("Version","StdDev", "Median", "Mean")


cwe_smry <- smry_table(cwe_det_dat_long, sd, TRUE)
cwe_smry_median <- smry_table(cwe_det_dat_long, median, TRUE)
cwe_smry_mean <- smry_table(cwe_det_dat_long, mean, TRUE)
cwe_smry <- left_join(cwe_smry, cwe_smry_median, by = c("Id", "version"))
cwe_smry <- left_join(cwe_smry, cwe_smry_mean, by = c("Id", "version"))
names(cwe_smry)[2:5] <- c("Version","StdDev", "Median", "Mean")

cve_det_dat_long$Severity[is.na(cve_det_dat_long$Severity)] <- "NOT REPORTED"
cve_det_dat_long$Severity <- factor(cve_det_dat_long$Severity, levels = c("CRITICAL", "HIGH", "MEDIUM", "LOW", "NOT REPORTED"))

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


cve_det_dat_severSmry$Severity <- factor(cve_det_dat_severSmry$Severity, levels = c("CRITICAL", "HIGH", "MEDIUM", "LOW"))

mycolors <- colorRampPalette(brewer.pal(9, "YlGnBu"))(10)
ggplot(cve_det_dat_severSmry, aes(x = value, fill = version))+
  geom_density(alpha = 0.25)+
  scale_fill_manual(values =  mycolors)+
  # geom_dotplot(binaxis='y', stackdir='center',
                            # position=position_dodge(1)) +
  facet_wrap(~Severity, ncol = 1)

ggplot(cve_det_dat_severSmry,
       aes(y= version, x = value)) +
  geom_violin(aes(group = version, fill = version), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  # geom_dotplot(aes(fill = version), shape = 21, size = 2.25, height = 0.2, width = 0) +
  scale_fill_manual(values = mycolors)+
  labs(x = "", y = "") +
  theme(legend.position="right" )+
  guides(fill=guide_legend(title="Version"))+
  labs(x = "Standard Deviation in Findings", y = "CVE Severity") +
  facet_wrap(~Severity, nrow = 1)

ggplot(cve_det_dat_severSmry[cve_det_dat_severSmry$version %in% c("1.0", "2.0", "3.0"),],
       aes(y= Severity, x = value)) +
  geom_violin(aes(group = Severity, fill = Severity),) +
  scale_fill_viridis_d(name = "Severity", option = "turbo", begin = 0.45, end = 0.95, direction = -1)+
  theme(legend.position="top")+
  guides(fill=guide_legend(title="Severity"))+
  labs(x = "Standard Deviation in Findings", y = "Severity") +
  facet_wrap(~version, ncol = 1)

ggplot(cve_det_dat_severSmry,
       aes(y= Severity, x = value)) +
  geom_violin(aes(group = Severity, fill = Severity),) +
  scale_fill_viridis_d(name = "Severity", option = "turbo", begin = 0.45, end = 0.95, direction = -1)+
  theme(legend.position="top")+
  guides(fill=guide_legend(title="Severity"))+
  labs(x = "Standard Deviation in Findings", y = "Severity") +
  facet_wrap(~version, ncol = 1)

p1 <- ggplot(cwe_smry[cwe_smry$Id %in% c("457", "676"),],
             aes(y= Id, x = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.2, width = 0.1) +
  scale_fill_brewer(palette = "YlGnBu")+
  labs(x = "", y = "") +
  theme(legend.position="top")+
  guides(fill=guide_legend(title="Version"))

p2 <- ggplot(cwe_smry[!(cwe_smry$Id %in% c("457", "676")),],
             aes(y= Id, x = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.2, width = 0.1) +
  scale_fill_brewer(palette = "YlGnBu")+
  labs(x = "", y = "") +
  labs(x = "Standard Deviation in Findings", y = "             CWE Id") +
  theme(legend.position="none")

ggarrange(p1, p2, ncol = 1, heights = c(2, 19))

mycolors <- colorRampPalette(brewer.pal(9, "YlGnBu"))(11)
ggplot(cve_smry_by_yr,
       aes(y= Id, x = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.2, width = 0.1) +
  scale_fill_manual(values = mycolors)+
  labs(x = "", y = "") +
  theme(legend.position="top")+
  guides(fill=guide_legend(title="Version"))+
  labs(x = "Standard Deviation in Findings", y = "CVE Prefix (Year)")

cve_pts_plt <-
  ggplot(cve_smry_by_yr,
         aes(y= Id, x = Version, color = Median, size = StdDev)) +
  geom_point()+
  scale_size_continuous(name = "Std Dev") +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(legend.direction = "vertical", legend.box = "vertical")+
  labs(x = "Version", y = "CVE Prefix (Year)")
cve_pts_plt

cwe_pts_plt1 <-
  ggplot(cwe_smry[cwe_smry$Id %in% c("457", "676"),],
         aes(y= Id, x = Version, color = Median, size = StdDev)) +
  geom_point()+
  scale_size_continuous(name = "Std Dev") +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(legend.direction = "vertical", legend.box = "horizontal")+
  labs(x = "", y = "")+
  guides(
    color = guide_colorbar(order = 1),
    fill = guide_legend(order = 0)
  )
cwe_pts_plt2 <-ggplot(cwe_smry[!(cwe_smry$Id %in% c("457", "676")),],
                      aes(y= Id, x = Version, color = Median, size = StdDev)) +
  geom_point()+
  scale_size_continuous(name = "Std Dev") +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(legend.direction = "vertical", legend.box = "horizontal")+
  labs(x = "Version", y = "               CWE Id")+
  guides(
    color = guide_colorbar(order = 1),
    fill = guide_legend(order = 0)
  )
ggarrange(cwe_pts_plt1, cwe_pts_plt2, ncol = 1, heights = c(6, 16))



