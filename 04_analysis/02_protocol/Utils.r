# only works for 3 clusters, can be made more robust later
clust_titles <- function(clustering) {
  medoids <- data.frame(
    id = 1:3,
    value = clustering$medoids[,1]
  )
  medoids <- medoids %>% arrange(value)
  medoids$title <- factor(c("low", "medium", "high"), levels=c("high", "medium", "low"))
  joined <- left_join(
    data.frame(
      id = clustering$cluster
    ),
    medoids
  )
  joined$title
}
