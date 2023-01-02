library(rjson)
library(dplyr)
library(tibble)
library(purrr)
library(tidyr)
library(ggplot2)
library(tidyselect)
library(egg)

cwe_det_dat <- fromJSON(file = "tool-evolution/01_acquisition/04_product/cwe_checker_breakdown.json")

nestedlist_to_tibble <- function(nestedlist, list_name) {
  nestedlist %>%
    bind_rows %>%
    mutate(filename = names(nestedlist),
           version = list_name)
}

cwe_det_dat <-
  cwe_det_dat %>%
  imap_dfr(nestedlist_to_tibble)

# run critical error check
cwe_smry_dat <- select(cwe_det_dat, starts_with("[")) %>%
  rowSums()
identical(cwe_det_dat$TOTAL_FINDINGS, cwe_smry_dat)

cwe_det_dat_long <-
  cwe_det_dat %>%
  select(c(starts_with("["), "filename", "version")) %>%
  pivot_longer(cols = starts_with("["), names_to = "CWE_Id")

ggplot(cwe_det_dat_long,
       aes(x = version, y = value)) +
  facet_wrap( ~ CWE_Id, scales = "free_y") +
  geom_line(mapping = aes(group = filename), color="black", alpha=0.2, size=0.5) +
  labs(y = "Findings", x = "") +
  theme(
    axis.text.x = element_text(angle = 40, hjust=1),
    # axis.text.x=element_blank(),
    panel.grid.major = element_blank(),
    panel.grid.minor = element_blank(),
    panel.background = element_blank(),
    plot.margin = unit(c(7, 5, -12, 1), "pt")
  ) +
  scale_x_discrete(expand = expansion(c(0.01,0)))

with(cwe_det_dat_long, tapply(value, list(CWE_Id, version), sum))
with(cwe_det_dat_long, tapply(value, list(CWE_Id, version), median))
with(cwe_det_dat_long, tapply(value, list(CWE_Id, version), mean))

cwe_smry <-
  as_tibble(
    with(
      cwe_det_dat_long,
      tapply(value, list(CWE_Id, version), sd)),
    rownames = NA
  ) %>%
  arrange(., apply(., 1, max)) %>%
  rownames_to_column(var = "CWE_Id") %>%
  mutate(CWE_Id = factor(CWE_Id, levels = CWE_Id)) %>%
  pivot_longer(!CWE_Id, names_to = "version")


p1 <- ggplot(cwe_smry[cwe_smry$CWE_Id %in% c("[CWE457]", "[CWE676]"),],
       aes(y= CWE_Id, x = value)) +
  geom_line(aes(group = CWE_Id), size = 1.25) +
  geom_point(aes(color = version), size = 3) +
  scale_color_brewer(palette = "YlGnBu")+
  labs(x = "", y = "") +
  theme(legend.position="top")+
  guides(color=guide_legend(title="Version"))

p2 <- ggplot(cwe_smry[!(cwe_smry$CWE_Id %in% c("[CWE457]", "[CWE676]")),],
             aes(y= CWE_Id, x = value)) +
  geom_line(aes(group = CWE_Id), size = 1.25) +
  geom_point(aes(color = version), size = 3)+
  scale_color_brewer(palette = "YlGnBu")+
  labs(x = "Standard Deviation in Findings", y = "             CWE") +
  theme(legend.position="none")

ggarrange(p1, p2, ncol = 1, heights = c(2, 19))
