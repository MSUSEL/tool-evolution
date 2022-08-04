# CVE bin tool wrangling notes

## Manual Steps

There are two "manual" steps in cve_bin_tool.r (which wrangles the acquisition data into long and wide formats).

### 1. Select which data to input

This is done via the `use_date` variable. This variable is used to select which data to import.

### 2. remove unwanted columns from the data (columns correspond to versions)

This is done with a select statement on the same line that the data is imported from the JSON. There is a comment highlighting this line. I (Travis) do not consider this a manual step but Ann Marie says it is.

## Thought processes

Version 3.1 was thrown out because it reported 0 for all binaries.
