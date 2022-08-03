# Load Libraries -------------------------------------------------------------------

library(tidyr)
library(plyr)
library(dplyr)
library(clValid)
library(ggplot2)
library(grid)
library(egg)
library(stringr)

library(ggpubr)
library(factoextra)

# set seed
# Unix time stamp from while writing this code
set.seed(132414231234)


# Data import and tidying -------------------------------------------------

# Import the data and store in a list
scores_wide <- 
  # get the index nums for the file names with wide data
  list.files("./03_clustering/01_input/") %>%
  # get the file names for the wide data using index nums
  .[grep("wide", .)] %>%
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./03_clustering/01_input/", fileNm, sep = "/"))}) %>%
  # make the names of the binaries the row names in each df
  # sort data frames by row names 
  lapply(., function(df) { 
    rownames(df) <- df$filename; return(df) }) %>%
  lapply(., function(df) {    df[ sort(row.names(df)), ]}) %>%
  # keep only the numeric columns in each df
  lapply(., function(df) {df[, sapply(df, is.numeric)]}) 

scores_long <- 
  # get the index nums for the file names with wide data
  list.files("./03_clustering/01_input/") %>% 
  # get the file names for the wide data using index nums
  .[grep("long", .)] %>%
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./03_clustering/01_input/", fileNm, sep = "/"))})

names(scores_long) <- names(scores_wide) <- c("cve_bin_tool", "cwe_checker")

scores_long <- lapply(names(scores_long), 
                      function(toolNm) {
                        cbind(
                          scores_long[[toolNm]],
                          toolName = toolNm)
                      }
) %>%
  do.call(rbind, .)

# Cluster Static Analysis Tool Scores Across All Tool Versions ------------

# set desired number of clusters. The order of the numofclust vector matters and
# should match up with the order of the tools in the scores_wide list
numOfClusts <- c(5, 3)

# do the clustering
kmeans_results <-
  # iterate over the scores for the different tools
  mapply(kmeans, scores_wide, numOfClusts, SIMPLIFY = FALSE)

# create list with cluster membership for each binary based on clustering above
clustIdsDfList <- 
  lapply(
    kmeans_results, function(res) data.frame(res$cluster)) %>%
  # lapply(t) %>%
  # lapply(as.data.frame) %>%
  lapply(., function(df){ df$filename <- row.names(df); 
  # pivot_longer(df, !filename, values_to = "cluster_membership");
  return(df)
  }
  ) 

# store cluster membership in data frame 
clustIdsDf <-  
  lapply(
    names(clustIdsDfList), 
    function(toolNm) {
      cbind(
        clustIdsDfList[[toolNm]],
        toolName = toolNm)
    }
  ) %>%
  do.call(rbind, .)

# put cluster membership back in the long data frame and assign it to a new object
scores_long_withClusts <- left_join(scores_long, clustIdsDf, by = c("filename", "toolName"))
names(scores_long_withClusts)[names(scores_long_withClusts) == "res.cluster"] <- "clusterIdx"
# store cluster membership as a factor (the cluster number is meaningless to us;
# we just want to know which groups the binaries belong to)
scores_long_withClusts$clusterIdx <- factor(scores_long_withClusts$clusterIdx )

# These are hard coded labels
cluster_names <- data.frame(
  toolName = c("cve_bin_tool", "cve_bin_tool", "cve_bin_tool", 
                  "cwe_checker", "cwe_checker", "cwe_checker"),
  clusterIdx = c(1, 2, 3, 1, 2, 3),
  cluster_title = c("medium", "low", "high", "low", "medium", "high")
)

cluster_names$cluster_title <- factor(cluster_names$cluster_title, levels=c("high", "medium", "low"))

scores_long_withClusts$clusterIdx <- 
  as.numeric(scores_long_withClusts$clusterIdx)

scores_long_withClusts$cluster_title <- NULL

scores_long_withClusts <- join(scores_long_withClusts, cluster_names)

## standard deviation

sapply(c(cve_bin_long, cwe_checker_long), function (tool_data) {
  sapply(c(1, 2, 3), function (clust_id) {
    df_subset <- tool_data[tool_data$cluster_id == clust_id,]
    sd(df_subset$vuln_count)
  })
})


#### TEMP (out of order)

# use clValid to help us have an ideo of the optimal cluster numbers
kmeans_opt_clustNums <- 
  # iterate over the scores for the different tools
  llply(
    scores_wide, function(scores) { 
      # allow cluster number to vary from 2 to 5
      out <- clValid(obj = scores, nClust = 2:5, 
                     clMethods = "kmeans",
                     validation = c("internal", "stability"))
      out <-getRanksWeights(out) 
      print(out$ranks, quote = FALSE)
    }
  )

