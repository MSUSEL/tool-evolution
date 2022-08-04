# this file should import all data needed to make all product and 
# incremental graphs

cve_bin <- read.csv("./02_wrangling/04_product/cve_bin_tool_wide_1658175857.csv")
cve_bin_long <- read.csv("./02_wrangling/04_product/cve_bin_tool_long_1658175857.csv")

cwe_checker <- read.csv("./04_analysis/01_input/cwe_checker_wide.csv")
cwe_checker_long <- read.csv("./04_analysis/01_input/cwe_checker_long.csv")
