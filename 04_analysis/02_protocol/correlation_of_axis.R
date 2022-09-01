library(ggplot2)
library(tidyr)

## remember to run /analysis/input/setup.r

# Pure Version comparison (versions are each axis)
## (coloring might be confusing, consider removing if not helping)
cve_bin %>% left_join(binaryAttrs) %>%
  ggplot(mapping = aes(x = version_3.1.1, y = version_2.0, color = size)) +
  geom_jitter()

cwe_checker %>% left_join(binaryAttrs) %>%
  ggplot(mapping = aes(x = version_0.4, y = version_0.6, color = size)) +
  geom_jitter()

  
# Size on x axis
cve_bin %>% left_join(binaryAttrs) %>%
  ggplot(mapping = aes(x = size, y = version_3.1.1, color = version_2.0)) +
  geom_jitter()

cwe_checker %>% left_join(binaryAttrs) %>% 
  ggplot(mapping = aes(x = size, y = version_0.6, color = version_0.4)) +
  geom_jitter()


