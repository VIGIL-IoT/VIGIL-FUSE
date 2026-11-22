# Vector PDF plots, using only packages shipped with R.
plot_bars <- function(values, labels, title, ylab, path, ylim = NULL) {
  pdf(path, width = 8, height = 5, onefile = TRUE)
  par(mar = c(7, 4.5, 3, 1), family = "sans", las = 2)
  if (all(is.na(values))) { plot.new(); title(main = title); text(.5, .5, "No defined values") }
  else barplot(values, names.arg = labels, col = "#287b8e", border = NA,
               main = title, ylab = ylab, ylim = ylim, cex.names = .8)
  dev.off()
}
plot_distributions <- function(x, field, title, ylab, path) {
  pdf(path, width = 8, height = 5, onefile = TRUE)
  par(mar = c(7, 4.5, 3, 1), family = "sans", las = 2)
  usable <- x[!is.na(x[[field]]), , drop = FALSE]
  if (!nrow(usable)) { plot.new(); title(main = title); text(.5, .5, "No measurements") }
  else boxplot(split(usable[[field]], usable$configuration), col = "#88bdc5", border = "#28535e", main = title, ylab = ylab, cex.axis = .8)
  dev.off()
}
