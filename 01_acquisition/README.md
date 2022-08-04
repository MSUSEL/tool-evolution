# Data Acquisition

## CVE Bin Tool

Running cve-bin-tool-runner.py is self-contained. Running this will generate output into the folder `01_acquisition/03_incremental`. This data will have the UNIX timestamp of when the run completed in the title of the data. Per best practice, if that data is to be wrangled, move that folder into `01_acquisition/03_incremental`. See `02_wrangling/02_protocol/cve_bin.md` for how to wrangle this data.

If anything seems awry, manually test cve-bin-tool on some of the binaries using the version that you want. The line `pip install cve-bin-tool=={{wanted version}}` will let you download any version that you want.

### Pip Releases as of 06/02/2022

0.2.0, 0.3.0, 0.3.1, 1.0, 1.1, 2.0a0, 2.0, 2.1, 2.1.post1, 2.2, 2.2.1, 3.0, 3.1rc2, 3.1rc3, 3.1, 3.1.1

source: https://pypi.org/project/cve-bin-tool/#history