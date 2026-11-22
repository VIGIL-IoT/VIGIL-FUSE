args <- commandArgs(trailingOnly = TRUE)
if (!length(args)) stop("Usage: Rscript analyze_accuracy.R <dataset.csv> [output-directory]")
script <- sub("^--file=", "", grep("^--file=", commandArgs(), value = TRUE)[1])
root <- dirname(dirname(normalizePath(script)))
source(file.path(root, "common", "analysis.R")); source(file.path(root, "plots", "plots.R"))
x <- validate_accuracy(read_dataset(args[1], c("case_id", "configuration", "prediction", "ground_truth", "status")))
out <- output_dir(args, "accuracy-output")
groups <- split(x, x$configuration)
summary <- do.call(rbind, lapply(names(groups), function(g) {
  z <- groups[[g]]; m <- metrics(z)
  intervals <- unlist(lapply(c("precision", "recall", "f1", "fpr", "fnr", "coverage", "unknown_partial_rate"), function(k) {
    ci <- bootstrap_ci(z, function(sample) metrics(sample)[[k]])
    setNames(ci, paste0(k, c("_lower", "_upper", "_bootstrap_valid")))
  }))
  data.frame(configuration = g, as.list(c(m, intervals)), check.names = FALSE)
}))
write.csv(summary, file.path(out, "accuracy-summary.csv"), row.names = FALSE, na = "")
configs <- sort(unique(x$configuration))
if (length(configs) >= 2) {
  x$correct <- ifelse(x$status == "COMPLETE" & !is.na(x$prediction) & !is.na(x$ground_truth), as.numeric(x$prediction == x$ground_truth), NA_real_)
  pairs <- do.call(rbind, lapply(configs[-1], function(g) paired_difference(x, "correct", configs[1], g)))
  write.csv(pairs, file.path(out, "paired-accuracy.csv"), row.names = FALSE, na = "")
  plot_bars(pairs$difference, pairs$comparison, paste("Paired accuracy difference vs", configs[1]), "Difference in accuracy", file.path(out, "before-after.pdf"))
}
plot_bars(c(summary$precision, summary$recall), c(paste(summary$configuration, "precision"), paste(summary$configuration, "recall")), "Precision and recall", "Proportion", file.path(out, "precision-recall.pdf"), c(0, 1))
plot_bars(summary$coverage, summary$configuration, "Complete analysis coverage", "Proportion of cases", file.path(out, "coverage.pdf"), c(0, 1))
if ("severity" %in% names(x)) {
  counts <- table(x$severity[x$prediction == 1 & !is.na(x$prediction)])
  if (length(counts)) plot_bars(as.numeric(counts), names(counts), "Finding distribution by severity", "Case findings", file.path(out, "finding-distribution.pdf"))
}
if ("analyzer" %in% names(x)) {
  counts <- table(x$analyzer[x$prediction == 1 & !is.na(x$prediction)])
  if (length(counts)) plot_bars(as.numeric(counts), names(counts), "Findings attributed to analyzer", "Case findings", file.path(out, "analyzer-contribution.pdf"))
}
cat("Accuracy outputs:", normalizePath(out), "\n")
