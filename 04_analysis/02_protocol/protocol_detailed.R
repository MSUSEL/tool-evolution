#
# Setup -------------------------------------------------------------------

source("./tool-evolution/04_analysis/02_protocol/setup.R")
source("./tool-evolution/04_analysis/02_protocol/functions.R")

product_path <- "./tool-evolution/04_analysis/04_product/"


########### PLOT TO INCLUDE IN PAPER
sever_violin_plt <-
  ggplot(cve_det_dat_severSmry[cve_det_dat_severSmry$version %in% c("1.0", "2.0", "3.0"),],
         aes(x= Severity, y = value)) +
  geom_violin(aes(group = Severity, fill = Severity),) +
  scale_fill_viridis_d(name = "Severity", option = "turbo", begin = 0.45, end = 0.95, direction = -1)+
  theme(axis.text.x = element_text(angle = 40, hjust=1),
        legend.position="top")+
  guides(fill=guide_legend(title="Severity"))+
  labs(y = "Std Dev in Findings", x = "Severity") +
  facet_wrap(~version, nrow = 1)
sever_violin_plt
pdf(
  file = paste0(product_path, "sever_violin_plt", ".pdf"),
  height = 3,
  width = 4.25)
sever_violin_plt
dev.off()

########### PLOT TO INCLUDE IN PAPER
p1 <- ggplot(cwe_smry[cwe_smry$Id %in% c("457", "676"),],
             aes(x= Id, y = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.0, width = 0.3) +
  scale_fill_brewer(palette = "YlGnBu")+
  labs(y = "", x = "") +
  theme(axis.text.x = element_text(angle = 40, hjust=1), legend.position="right",
        # legend.box.spacing = unit(15,"points"),
        plot.margin = unit(c(5.5, 5.5, 5.5, -10), "points"))+
  guides(fill=guide_legend(title="Version"))

p2 <- ggplot(cwe_smry[!(cwe_smry$Id %in% c("457", "676")),],
             aes(x= Id, y = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.0, width = 0.3) +
  scale_fill_brewer(palette = "YlGnBu")+
  labs(x = "", y = "") +
  labs(y = "St Dev in Findings", x = "                CWE Id") +
  theme(axis.text.x = element_text(angle = 40, hjust=1), legend.position="none",
        plot.margin = unit(c(5.5, -3, 5.5, 5.5), "points"))

mycolors <- colorRampPalette(brewer.pal(9, "YlGnBu"))(11)
std_dev_cve_plt <-
  ggplot(cve_smry_by_yr,
         aes(x= Id, y = StdDev)) +
  geom_line(aes(group = Id), size = 0.5) +
  # geom_point(aes(fill = version), shape = 21, size = 2) +
  geom_jitter(aes(fill = Version), shape = 21, size = 2.25, height = 0.0, width = 0.3) +
  scale_fill_manual(values = mycolors)+
  labs(x = "", y = "") +
  theme(axis.text.x = element_text(angle = 40, hjust=1),
        legend.position="top",
        # legend.position = c(0.12,0.62), legend.direction = "vertical",
        plot.margin = unit(c(5.5, 5.5, 5.5, 5.5), "points"))+
  guides(fill=guide_legend(title="Version", nrow =1))+
  # guides(fill=guide_legend(title=element_blank()))+
  labs(y = "St Dev in Findings", x = "CVE Prefix (Year)")

std_dev_combo_plt <-
  ggarrange(
    ggarrange(p2, p1, nrow = 1, widths = c(12, 2), common.legend = TRUE),
    std_dev_cve_plt,
    ncol =1,
    labels = c("A", "B")
    )

pdf(
  file = paste0(product_path, "std_dev_combo_plt", ".pdf"),
  height = 6,
  width = 7)
std_dev_combo_plt
dev.off()

########### PLOT TO INCLUDE IN PAPER
cve_pts_plt <-
  ggplot(cve_smry_by_yr,
         aes(y= Id, x = Version, color = Median, size = Spread)) +
  geom_point()+
  scale_size_continuous(name = "Detections", limits = c(0.0001, 100)) +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(
    axis.text.x = element_text(angle = 40, hjust=1),
    legend.direction = "horizontal",
    legend.box = "vertical",
    legend.position = "top",
    legend.margin=margin(c(-5,0,1,0)),
    legend.box.spacing = unit(0, "pt")
  )+
  labs(x = "Version", y = "CVE Prefix (Year)")

cwe_pts_plt <-
  ggplot(cwe_smry,
         aes(y= Id, x = Version, color = Median, size = Spread)) +
  geom_point()+
  scale_size_continuous(name = "Detections", limits = c(0.0001,100)) +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(
    axis.text.x = element_text(angle = 40, hjust=1),
    legend.direction = "horizontal",
    legend.box = "vertical",
    legend.position = "top",
    legend.margin=margin(c(-5,0,1,0)),
    legend.box.spacing = unit(0, "pt")
  )+
  labs(x = "Version", y = "CWE Id")+
  guides(
    color = guide_colorbar(order = 1),
    fill = guide_legend(order = 0)
  )

cwe_pts_plt1 <-
  ggplot(cwe_smry[cwe_smry$Id %in% c("457", "676"),],
         aes(y= Id, x = Version, color = Median, size = Spread)) +
  geom_point()+
  scale_size_continuous(name = "Detections", limits = c(0.0001,100)) +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(
    axis.text.x = element_text(angle = 40, hjust=1),
    legend.direction = "horizontal",
    legend.box = "vertical",
    legend.position = "top",
    legend.margin=margin(c(-5,0,1,0)),
    legend.box.spacing = unit(0, "pt")
  )+
  labs(x = "Version", y = "CWE Id")+
  guides(
    color = guide_colorbar(order = 1),
    fill = guide_legend(order = 0)
  )
cwe_pts_plt2 <-ggplot(cwe_smry[!(cwe_smry$Id %in% c("457", "676")),], #"787", "125", "476","416", "190", "782"
                      aes(y= Id, x = Version, color = Median, size = Spread)) +
  geom_point()+
  scale_size_continuous(name = "Detections", limits = c(0.0001,100)) +
  scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
  # theme(legend.position="top")+
  theme(
    axis.text.x = element_text(angle = 40, hjust=1),
    legend.direction = "horizontal",
    legend.box = "vertical",
    legend.position = "top",
    legend.margin=margin(c(-5,0,1,0)),
    legend.box.spacing = unit(0, "pt")
  )+
  labs(x = "Version", y = "CWE Id")+
  guides(
    color = guide_colorbar(order = 1),
    fill = guide_legend(order = 0)
  )

how_widespread_common_all_together <-
  ggarrange(
    ggarrange(cwe_pts_plt1, cwe_pts_plt2, nrow = 2, ncol = 1, heights = c(3.1, 8)),
    cve_pts_plt,
    nrow =1,
    labels = c("A", "B")
    )
how_widespread_common_all_together

pdf(
  file = paste0(product_path, "how_widespread_common_all_together", ".pdf"),
  height = 8.25,
  width = 6)
how_widespread_common_all_together
dev.off()




# Points plots with size being standard deviation (instead of the percent of
# binaries have at least one finding)

# cve_pts_plt <-
#   ggplot(cve_smry_by_yr,
#          aes(y= Id, x = Version, color = Median, size = StdDev)) +
#   geom_point()+
#   scale_size_continuous(name = "Std Dev") +
#   scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
#   # theme(legend.position="top")+
#   theme(
#     axis.text.x = element_text(angle = 40, hjust=1),
#     legend.direction = "horizontal",
#     legend.box = "vertical",
#     legend.position = "top",
#     legend.margin=margin(c(-5,0,1,0)),
#     legend.box.spacing = unit(0, "pt")
#   )+
#   labs(x = "Version", y = "CVE Prefix (Year)")
# cve_pts_plt
#
# cwe_pts_plt1 <-
#   ggplot(cwe_smry[cwe_smry$Id %in% c("457", "676"),],
#          aes(y= Id, x = Version, color = Median, size = StdDev)) +
#   geom_point()+
#   scale_size_continuous(name = "Std Dev") +
#   scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
#   # theme(legend.position="top")+
#   theme(
#     axis.text.x = element_text(angle = 40, hjust=1),
#     legend.direction = "horizontal",
#     legend.box = "vertical",
#     legend.position = "top",
#     legend.margin=margin(c(-5,0,1,0)),
#     legend.box.spacing = unit(0, "pt")
#   )+
#   labs(x = "Version", y = "CWE Id")+
#   guides(
#     color = guide_colorbar(order = 1),
#     fill = guide_legend(order = 0)
#   )
# cwe_pts_plt2 <-ggplot(cwe_smry[!(cwe_smry$Id %in% c("457", "676")),], #"787", "125", "476","416", "190", "782"
#                       aes(y= Id, x = Version, color = Median, size = StdDev)) +
#   geom_point()+
#   scale_size_continuous(name = "Std Dev") +
#   scale_color_viridis_c(name = "Median", option = "turbo", begin = 0.025, end = 0.95)+
#   # theme(legend.position="top")+
#   theme(
#     axis.text.x = element_text(angle = 40, hjust=1),
#     legend.direction = "horizontal",
#     legend.box = "vertical",
#     legend.position = "top",
#     legend.margin=margin(c(-5,0,1,0)),
#     legend.box.spacing = unit(0, "pt")
#   )+
#   labs(x = "Version", y = "CWE Id")+
#   guides(
#     color = guide_colorbar(order = 1),
#     fill = guide_legend(order = 0)
#   )
#
# ggarrange(
#   ggarrange(cwe_pts_plt1, cwe_pts_plt2, nrow = 2, ncol = 1, heights = c(3.1, 8)),
#   cve_pts_plt,
#   nrow =1,
#   labels = c("A", "B"))
