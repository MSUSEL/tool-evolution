
library(tidyr)
library(plyr)
library(dplyr)
library(clValid)
library(ggplot2)
library(grid)
library(egg)
library(stringr)
library(plotly)
library (rjson)
library(ggpubr)
library(factoextra)

### Build wide and long formats
# CWE_CHECKER
cwe_checker <- fromJSON(file = "./01_acquisition/04_product/cwe_checker_parsed_results.json") %>%
  lapply(as.data.frame) %>%
  do.call(rbind,.)

cwe_checker$filename <- row.names(cwe_checker)
names(cwe_checker) <- gsub('X', 'version_', names(cwe_checker))
version_dates <- data.frame(version_0.6 = '2022-06-10', version_0.5 = '2021-07-05', version_0.4 = '2021-01-07') %>%
  t() %>%
  as.data.frame()

names(version_dates)[names(version_dates) == 'V1'] <- 'date'

version_dates$version <- row.names(version_dates)

as.Date(version_dates$date)

cwe_checker_long <- pivot_longer(cwe_checker, !filename, names_to = "version", values_to = "vuln_count") %>%
  left_join(version_dates)

# CVE_BIN_TOOL
cve_bin <- fromJSON(file = "./01_acquisition/04_product/cve_bin_tool_results_1655757361.json") %>% 
  lapply(as.data.frame) %>%
  do.call(rbind, .)

cve_bin <- cve_bin[, names(cve_bin)!="X3.1"]
version_dates <- data.frame(
  "3.1.1"="4-20-2022",
  "3.1"="4-19-2022",
  "3.0"="12-14-2021",
  "2.2.1"="8-4-2021",
  "2.2"="7-8-2021",
  "2.1.post1"="4-27-2021",
  "2.1"="12-7-2020",
  "2.0"="11-12-2020",
  "1.1"="10-15-2020",
  "1.0"="4-30-2020"
)

names(version_dates) <- gsub("X", "version_", names(version_dates))
version_dates <- t(version_dates)
dates <- as.Date(version_dates, format = "%m-%d-%Y") %>% as.data.frame
dates$version <- rownames(version_dates)
names(dates)[1] <- "date"

# make file names be a column
names(cve_bin) <- gsub("X", "version_", names(cve_bin))
cve_bin$filename <- rownames(cve_bin)

# go to long form
cve_bin_long <- cve_bin %>% 
  pivot_longer(!filename, names_to="version", values_to="vuln_count")
cve_bin_long <- left_join(cve_bin_long, dates)



### Build scores in long and wide format

scores_wide <- 
  # get the index nums for the file names with wide data
  list.files("./03_analysis/01_input/csvs_final_data") %>% 
  # get the file names for the wide data using index nums
  .[grep("wide", .)] %>% 
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./03_analysis/01_input/csvs_final_data", fileNm, sep = "/"))}) %>%
  # make the names of the binaries the row names in each df
  # sort data frames by row names 
  lapply(., function(df) { 
    rownames(df) <- df$filename; return(df) }) %>%
  lapply(., function(df) {    df[ sort(row.names(df)), ]}) %>%
  # keep only the numeric columns in each df
  lapply(., function(df) {df[, sapply(df, is.numeric)]}) 

scores_long <- 
  # get the index nums for the file names with wide data
  list.files("./03_analysis/01_input/csvs_final_data") %>% 
  # get the file names for the wide data using index nums
  .[grep("long", .)] %>% 
  # read csvs to data frames
  lapply(., function(fileNm) {read.csv(paste("./03_analysis/01_input/csvs_final_data", fileNm, sep = "/"), row.names = "X")})

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

datAttr <- read.csv("./03_analysis/01_input/BinaryAttrs.csv")


# Cluster Static Analysis Tool Scores Across All Tool Versions ------------

# use clValid to help us have an ideo of the optimal cluster numbers
kmeans_opt_clustNums <- 
  # iterate over the scores for the different tools
  llply(
    scores_wide, function(scores) { 
      # allow cluster number to vary from 2 to 5
      out <- clValid(obj = scores, nClust = 3:5, clMethods = "kmeans")
      out <-getRanksWeights(out) 
      print(out$ranks, quote = FALSE)
    }
  )

# set desired number of clusters. The order of the numofclust vector matters and
# should match up with the order of the tools in the scores_wide list
numOfClusts <- c(2, 5)
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


## Build Heatmap

scores_matrix <- data.matrix(versionDiffsAvgs)
x_lab <- list(title="cwe-checker", color="white")
y_lab <- list(title="cve-bin-tool", color="white")
ay <- list(
  side = "right",
  title = "Binaries",
  titlecolor=list(color="white")
  )

heatmap <- plot_ly(z = scores_matrix, type = "heatmap", y=row.names(scores_matrix), x=colnames(scores_matrix), 
           alpha = 0.5, colorscale = "Viridis", colorbar = list(title = "Vulnerability \n Differences", 
           titlefont=list(color="white"), tickfont=list(color="white"), tickcolor="white"))%>%
  layout(title = "Tool Versions Across Binaries", 
         paper_bgcolor="#105397", 
         titlefont = list(color = "white"),
         # xaxis = list(color="white"), 
         # yaxis = list(color="white"), 
         tickcolor = "white",
         xaxis = x_lab,
         yaxis = y_lab)%>%
  layout(yaxis2 = ay)

## Box Plot
# plot.new()
# my_box <- boxplot(cwe_checker[,1:3], cex.axis=1.5, cex.main=2, cex.sub=2, col = "white", box(col = "white"), outcol =  "white", col.axis = "white", col.lab = "white", staplecol = "white", par(bg ="#92BCDB"))
# box(lwd=2,col="white")
# title(main = "", col.main = "white")
# par(cex.main = 2)
# theme(axis.text.x = element_blank())

## GGPlots
# p1 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_line(mapping = aes(group = filename), color = 'black', alpha = 0.1, size = 2)+
#   ggtitle('CWE_CHECKER Vulnerabilities per version')
# 
# p2 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   stat_summary(fun = 'mean', geom = 'point')+
#   ggtitle('CWE_CHECKER version Means')
# 
# p3 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_violin()+
#   stat_summary(fun = 'mean', geom = 'point')+
#   ggtitle('CWE_CHECKER Violin Plot')
# 
# p4 <- 
#   ggplot(data = cwe_df_long, mapping = aes(x = version, y = vuln_count))+
#   geom_jitter()+
#   ggtitle('CWE_CHECKER Jitter Plot')
