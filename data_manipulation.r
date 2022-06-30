library(tidyverse)
library(rjson)

# Give the input file name to the function.
cve_bin_list <- fromJSON(file = "./cve-bin-tool-runner/data_outputs/full_results_1655757361.json")

cve_bin_dataframe <- lapply(cve_bin_list, as.data.frame)

cve_bin_dataframe2 <- do.call(rbind, cve_bin_dataframe)

