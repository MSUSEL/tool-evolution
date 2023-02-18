
# Setup -------------------------------------------------------------------
library(rjson)
library(dplyr)
library(tibble)
library(purrr)
library(tidyr)
library(ggplot2)
library(ggalluvial)
library(tidyselect)
library(egg)
library(ggpubr)
library(stringr)
library(RColorBrewer)

input_path <- "./tool-evolution/04_analysis/01_input/"
protocol_path <- "./tool-evolution/04_analysis/02_protocol/"
product_path <- "./tool-evolution/04_analysis/04_product/"

# First: move cleaned data into input for analysis. Do you want to overwrite the
# RData file in the input directory if it has already been created?
overwrite_value <- FALSE

# input file name and path
input_data <- paste0(input_path, "all_preprocessed_data.RData")

# do the copy
file.copy(
  from = "./tool-evolution/03_wrangling_aggregated/04_product/all_preprocessed_data.RData",
  to = input_data,
  overwrite = overwrite_value,
  copy.date = TRUE
)

load(input_data)


