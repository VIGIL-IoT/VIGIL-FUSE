args <- commandArgs(trailingOnly = TRUE)
if (!length(args)) stop("Usage: Rscript compare_runtime.R <dataset.csv> [output-directory]")
script <- sub("^--file=", "", grep("^--file=", commandArgs(), value = TRUE)[1])
root <- dirname(dirname(normalizePath(script)))
source(file.path(root, "common", "analysis.R")); source(file.path(root, "plots", "plots.R"))
x <- read_dataset(args[1], c("case_id", "configuration", "runtime_ms", "memory_mb"))
if (anyNA(x$case_id) || anyNA(x$configuration) || any(!nzchar(trimws(x$case_id))) || any(!nzchar(trimws(x$configuration)))) stop("Missing case or configuration")
if (anyDuplicated(x[c("case_id", "configuration")])) stop("Duplicate case/configuration")
for (field in c("runtime_ms", "memory_mb")) {
  if (!is.numeric(x[[field]]) || any(!is.na(x[[field]]) & (!is.finite(x[[field]]) | x[[field]] < 0))) stop("Invalid ", field)
}
out <- output_dir(args, "runtime-output")
summary <- do.call(rbind, lapply(split(x, x$configuration), function(z) do.call(rbind, lapply(c("runtime_ms", "memory_mb"), function(field) {
  v <- z[[field]][!is.na(z[[field]])]
  data.frame(configuration = z$configuration[1], measurement = field, n = length(v), mean = if (length(v)) mean(v) else NA_real_, median = if (length(v)) median(v) else NA_real_, p95 = if (length(v)) unname(quantile(v, .95)) else NA_real_)
}))))
write.csv(summary, file.path(out, "measurement-summary.csv"), row.names = FALSE, na = "")
configs <- sort(unique(x$configuration))
if (length(configs) >= 2) {
  comparisons <- do.call(rbind, lapply(c("runtime_ms", "memory_mb"), function(field) do.call(rbind, lapply(configs[-1], function(g) cbind(measurement = field, paired_difference(x, field, configs[1], g))))))
  write.csv(comparisons, file.path(out, "paired-measurements.csv"), row.names = FALSE, na = "")
}
plot_distributions(x, "runtime_ms", "Runtime distribution", "Milliseconds", file.path(out, "runtime.pdf"))
plot_distributions(x, "memory_mb", "Memory distribution", "Megabytes", file.path(out, "memory.pdf"))
cat("Benchmark outputs:", normalizePath(out), "\n")
