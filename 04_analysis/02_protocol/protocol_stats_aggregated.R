# load necessary libraries
library(tidyverse)
library(lme4)
library(lmtest)
library(vegan)
library(stringr)

# set seed to Jenny's phone number (yeah, I listened to Tommy Tutone this morning)
set.seed(8675309)

# set wd
setwd("/home/amr/Documents/Research/CyberQA/REU_2022/toolEvoAMR/tool-evolution")

# import data
source("./04_analysis/01_input/setup.r")
cwe_check_wide <- cwe_checker
cve_bin_wide <- cve_bin
binary_attr <- read.csv("./04_analysis/01_input/BinaryAttrs.csv")

## wrangling
dim(binary_attr)
dim(cwe_check_wide)
dim(cve_bin_wide)

#############
# something is weird with the names of the binary files in this new cwe checker dataset
cwe_check_wide$filename[!(cwe_check_wide$filename %in% binary_attr$binary)]
binary_attr$binary[!(binary_attr$binary %in% cwe_check_wide$filename)]
#############

## trying removing periods and dashes in the filenames
cwe_check_wide$filename <-
  cwe_check_wide$filename %>%
  str_remove_all("[.]") %>%
  str_remove_all("[-]") %>%
  str_remove_all("[_]")

cve_bin_wide$filename <-
  cve_bin_wide$filename %>%
  str_remove_all("[.]") %>%
  str_remove_all("[-]") %>%
  str_remove_all("[_]")

binary_attr$binary <-
  binary_attr$binary %>%
  str_remove_all("[.]") %>%
  str_remove_all("[-]") %>%
  str_remove_all("[_]")


# shorten findings dataset to only those binaries for which we have attributes
cwe_check_wide <- cwe_check_wide[cwe_check_wide$filename %in% binary_attr$binary,]
cve_bin_wide <- cve_bin_wide[cve_bin_wide$filename %in% binary_attr$binary,]

# check to see that the same set of binaries was assessed by both tools
identical(sort(cve_bin_wide$filename), sort(cwe_check_wide$filename))

# subset to the shorter list of binaries
dim(cwe_check_wide)
dim(cve_bin_wide)

sum(!(cwe_check_wide$filename %in% cve_bin_wide$filename))  # all the cwe checker binary names are in the cve bin names
sum(!(cwe_check_wide$filename %in% binary_attr$binary))  # all the cwe checker binary names are in the attribute bin names


# shorten attributes to only those where we have findings (only need to check
# against one tool since they assessed the same suite of binaries)
binary_attr <- binary_attr[binary_attr$binary %in% cwe_check_wide$filename, ]
cve_bin_wide <- cve_bin_wide[cve_bin_wide$filename %in% cwe_check_wide$filename, ]

# order each data frame by the name of the binaries
cwe_check_wide <- cwe_check_wide[order(cwe_check_wide$filename), ]
cve_bin_wide <- cve_bin_wide[order(cve_bin_wide$filename), ]
binary_attr <- binary_attr[order(binary_attr$binary), ]

identical(cwe_check_wide$filename, binary_attr$binary)
identical(cve_bin_wide$filename, binary_attr$binary)

row.names(cwe_check_wide) <- cwe_check_wide$filename
row.names(cve_bin_wide) <- cve_bin_wide$filename

names(binary_attr)[names(binary_attr) == "binary"] <- "filename"

# drop all columns that we don't need
cwe_check_wide <- ( cwe_check_wide[, ! (names(cwe_check_wide) %in% c("X") )] )
cve_bin_wide <- ( cve_bin_wide[, !(names(cve_bin_wide) %in% c("X") )] )

cwe_check_long <-
  pivot_longer(
    data = cwe_check_wide,
    cols = starts_with("version"),
    names_to = "version",
    values_to = "findings_count"
    )

cve_bin_long <-
  pivot_longer(
    data = cve_bin_wide,
    cols = starts_with("version"),
    names_to = "version",
    values_to = "findings_count"
  )

cve_bin_long$version <- gsub("version_", "v", cve_bin_long$version)
cve_bin_long$version <- gsub("post1", "p1", cve_bin_long$version)

cwe_check_long$version <- gsub("version_", "  v", cwe_check_long$version)

names(cve_bin_wide) <- gsub("version_", "v", names(cve_bin_wide))
names(cve_bin_wide) <- gsub("post1", "p1", names(cve_bin_wide))

names(cwe_check_wide) <- gsub("version_", "  v", names(cwe_check_wide))


friedman.test(findings_count ~ version | filename, data = cwe_check_long)
friedman.test(findings_count ~ version | filename, data = cve_bin_long)
# "The median number of findings reported in binaries varied according to the
# version of the static analysis tool (CWE_Checker: Friedman chi-squared =
# 575.1, df = 2, p-value < 2.2e-16; CVE_Bin_Tool Friedman chi-squared = 4621.4,
# df = 8, p-value < 2.2e-16).

##################################################

#
# binary_attr$cve_sd <- apply(select(cve_bin_wide, !filename), 1, sd)
# cve_glm_out <- glm(cve_sd ~ compiler + static + domain, offset = log(size), data = binary_attr)
# summary(cve_glm_out)

#
# cwe_check_long <- left_join(cwe_check_long, binary_attr, by = c("filename"))
# cve_bin_long <- left_join(cve_bin_long, binary_attr, by = c("filename"))
#
#
# cwe_ver <-
#   glmer.nb(
#     findings_count ~ version + ( 1 | filename),
#     data = cwe_check_long,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=10e100))
#   )
# cwe_no_ver <-
#   glmer.nb(
#     findings_count ~ 1 + ( 1 | filename),
#     data = cwe_check_long,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=10e100))
#   )
#
# anova(cwe_ver, cwe_no_ver)
# lrtest(cwe_ver, cwe_no_ver)
#
#
# cve_ver <-
#   glmer.nb(
#     findings_count ~ version + ( 1 | filename),
#     data = cve_bin_long,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=10e100))
#   )
# cve_no_ver <-
#   glmer.nb(
#     findings_count ~ 1 + ( 1 | filename),
#     data = cve_bin_long,
#     control=glmerControl(optimizer="bobyqa",optCtrl=list(maxfun=10e100))
#   )
#
# anova(cve_ver, cve_no_ver)
# lrtest(cve_ver, cve_no_ver)
#
# cwe_in <- select(cwe_check_wide, !filename)
# cwe_dis_man <- dist(cwe_in, "manhattan")
# MASS::isoMDS(cwe_dis_man)
#
#
# cve_in <- t(select(cve_bin_wide, !filename))
# cve_attr <- data.frame(version = row.names(cve_in))
#
# cve_dis_euc <- dist(cve_in, "euclidean")
# summary(adonis2(cve_in ~ version, data = cve_attr))
