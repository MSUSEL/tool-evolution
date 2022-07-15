

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


# File Management ---------------------------------------------------------

# Move the files into the input folder
file.copy("/home/amr/Documents/Research/CyberQA/REU_2022/tool-evolution/csvs_final_data", "./01_input")
file.copy("/home/amr/Documents/Research/CyberQA/REU_2022/tool-evolution/BinaryAttrs.csv", "./01_input")



# Data import and tidying -------------------------------------------------

# Import the data and store in a list
scores_wide <- 
  # get the index nums for the file names with wide data
  list.files("./01_input/csvs_final_data") %>% 
  # get the file names for the wide data using index nums
  .[grep("wide", .)] %>% 
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./01_input/csvs_final_data", fileNm, sep = "/"))}) %>%
  # make the names of the binaries the row names in each df
  # sort data frames by row names 
  lapply(., function(df) { 
    rownames(df) <- df$filename; return(df) }) %>%
  lapply(., function(df) {    df[ sort(row.names(df)), ]}) %>%
  # keep only the numeric columns in each df
  lapply(., function(df) {df[, sapply(df, is.numeric)]}) 

scores_long <- 
  # get the index nums for the file names with wide data
  list.files("./01_input/csvs_final_data") %>% 
  # get the file names for the wide data using index nums
  .[grep("long", .)] %>% 
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./01_input/csvs_final_data", fileNm, sep = "/"), row.names = "X")})

names(scores_wide) <- names(scores_long) <- c("cve_bin_tool", "cwe_checker")

scores_long <-
  lapply(names(scores_long), 
         function(toolNm) {
           cbind(
             scores_long[[toolNm]],
             toolName = toolNm)
         }
  ) %>%
  do.call(rbind, .)

datAttr <- read.csv("./01_input/BinaryAttrs.csv")


# Cluster Static Analysis Tool Scores Across All Tool Versions ------------

# use clValid to help us have an ideo of the optimal cluster numbers
kmeans_opt_clustNums <- 
  # iterate over the scores for the different tools
  llply(
    scores_wide, function(scores) { 
      # allow cluster number to vary from 2 to 5
      out <- clValid(obj = scores, nClust = 2:5, clMethods = "kmeans")
      out <-getRanksWeights(out) 
      print(out$ranks, quote = FALSE)
    }
  )

# set desired number of clusters. The order of the numofclust vector matters and
# should match up with the order of the tools in the scores_wide list
numOfClusts <- c(3, 5)
# do the clustering
kmeans_results <-
  # iterate over the scores for the different tools
  mapply(kmeans, scores_wide, numOfClusts, SIMPLIFY = FALSE)
  # llply(scores_wide, kmeans, centers = numOfClusts)

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


# Plot clustering results -------------------------------------------------

# this section could use to be streamlined...but anyhow

# make 2 separate data frames for each of the tools
cve_bin_dat <- scores_long_withClusts[scores_long_withClusts$toolName == "cve_bin_tool", ]
cwe_check_dat <- scores_long_withClusts[scores_long_withClusts$toolName == "cwe_checker", ]

# some plots
p1_cve_bin <-
  ggplot(data = cve_bin_dat, mapping = aes(x = version, y = vuln_count))+
  geom_line(mapping = aes(group = filename, color = clusterIdx), alpha = 0.5, size = 1) +
  scale_x_discrete(guide = guide_axis(angle = 90)) +
  xlab("Version") + ylab("Vulnerability Count") +
  facet_grid(cols = vars(clusterIdx))

p1_cwe_check <-
  ggplot(data = cwe_check_dat, mapping = aes(x = version, y = vuln_count))+
  geom_line(mapping = aes(group = filename, color = clusterIdx), alpha = 0.5, size = 0.75) +
  scale_x_discrete(guide = guide_axis(angle = 90)) +
  xlab("Version") + ylab("Vulnerability Count") +
  facet_grid(cols = vars(clusterIdx))

grid.draw(ggarrange(plots = list(p1_cve_bin, p1_cwe_check), nrow = 2))

###### we don't seem to have attribute data for some binaries....
row.names(scores_wide[[2]])[!(row.names(scores_wide[[2]]) %in% datAttr$binary)]
#....and vice versa!....maybe talk to derek
datAttr$binary[!(datAttr$binary %in% row.names(scores_wide[[2]]))]

# joining attributes with data...colleen - I recommend doing standard deviation
# or variance
scores_avg_with_attr <- 
  lapply(scores_wide, 
         function(df) {
           mean_score <- apply(df[, names(df)!= "binary"], 1, mean)
           # df[,"binary"] <- row.names(df)
           mean_score <- as.data.frame(mean_score)
           mean_score[,"binary"] <- row.names(mean_score)
           return(mean_score)
         }
  )
scores_avg_with_attr <- 
  lapply(
    1:length(scores_avg_with_attr), 
    function(i) inner_join(scores_avg_with_attr[[i]], datAttr, by = "binary") 
  )
names(scores_avg_with_attr) <- c("cve_bin_tool", "cwe_checker")

linear_models <- lapply(
  scores_avg_with_attr, 
  function(df) {
    ### be sure to look at different model structures
    lm(mean_score ~ size + static + domain, data = df)
    }
)
lapply(linear_models, summary)


# Inter-tool comparison by version ----------------------------------------

# get versions to extract
versionCombos <- expand.grid(names(scores_wide[[1]]), names(scores_wide[[2]]))
names(versionCombos) <- c("cve_bin_tool", "cwe_checker")

# do the subtraction for each binary in each version of each tool
versionDiffs <-
  lapply(
    1:nrow(versionCombos), 
    function(i){
      valOut <-
        scores_wide[["cwe_checker"]][ , versionCombos$cwe_checker[i]] -
        scores_wide[["cve_bin_tool"]][, versionCombos$cve_bin_tool[i]]
      if(
        identical(
          row.names(scores_wide[["cwe_checker"]]), row.names(scores_wide[["cve_bin_tool"]])
        )
      ) {
        names(valOut) <- row.names(scores_wide[["cwe_checker"]])
      } else { 
        stop("Row names do not match for static analysis tool data frames.")  
      }
      return(valOut)
    }
  )
names(versionDiffs) <- paste(versionCombos$cwe_checker, "-", versionCombos$cve_bin_tool)

# store above in matrix
versionDiffsMatrix <- do.call(cbind, versionDiffs)

# take a look at the averages
versionDiffsAvgs <- apply(versionDiffsMatrix, 2, mean)
versionDiffsAvgs <- versionDiffsAvgs[sort(names(versionDiffsAvgs))]

# build data for heatmap
cwe_names <- unique(sub(" -.*", "", names(versionDiffsAvgs)  ))
cve_names <- unique(sub(".*- ", "", names(versionDiffsAvgs)  ))
versionDiffsAvgs <- as.data.frame(matrix(versionDiffsAvgs, 9, 3))
row.names(versionDiffsAvgs)  <- cve_names
names(versionDiffsAvgs) <- cwe_names


# cluster on raw differences between tools
versionDiffsClusts <- kmeans(versionDiffsMatrix, 3)

fviz_cluster(
  versionDiffsClusts, data = versionDiffsMatrix,
  geom = "point",
  ellipse.type = "convex", 
  ggtheme = theme_bw()
)

