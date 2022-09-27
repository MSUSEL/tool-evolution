# this file should import all data needed to make all product and
# incremental graphs

cve_bin <- read.csv("./02_wrangling/04_product/cve_bin_tool_wide_1658175857.csv")
cve_bin_long <- read.csv("./02_wrangling/04_product/cve_bin_tool_long_1658175857.csv")

cwe_checker <- read.csv("./02_wrangling/04_product/cwe_check_wide_1664248617.csv")
cwe_checker_long <- read.csv("./02_wrangling/04_product/cwe_check_long_1664248617.csv")
names(cwe_checker_long)[names(cwe_checker_long) == "findings_count"] <- "vuln_count"
