library(tidyverse)
library(rjson)
require(reshape2)

# Give the input file name to the function.
cve_bin_list <- fromJSON(file = "./cve-bin-tool-runner/data_outputs/full_results_1655757361.json")

cve_bin_dataframe <- lapply(cve_bin_list, as.data.frame)

cve_bin_dataframe2 <- do.call(rbind, cve_bin_dataframe)

avgs <- apply(cve_bin_dataframe2, 2, mean)

avgs_df <- as.data.frame(avgs)

avgs_df$version <- rownames(avgs_df)

ggplot(avgs_df, aes(x = version, y=avgs)) +
  geom_point()
