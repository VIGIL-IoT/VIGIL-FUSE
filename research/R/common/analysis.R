# Shared research functions. These do not run during FUSE scans.
read_dataset <- function(path, required) {
  x <- read.csv(path, stringsAsFactors = FALSE, na.strings = c("", "NA"), check.names = FALSE)
  missing <- setdiff(required, names(x))
  if (length(missing)) stop("Missing columns: ", paste(missing, collapse = ", "))
  if (!nrow(x)) stop("Dataset is empty")
  x
}
ratio <- function(n, d) if (d == 0) NA_real_ else n / d
metrics <- function(x) {
  known <- !is.na(x$prediction) & !is.na(x$ground_truth) & x$status == "COMPLETE"
  y <- x[known, , drop = FALSE]
  tp <- sum(y$prediction == 1 & y$ground_truth == 1)
  fp <- sum(y$prediction == 1 & y$ground_truth == 0)
  fn <- sum(y$prediction == 0 & y$ground_truth == 1)
  tn <- sum(y$prediction == 0 & y$ground_truth == 0)
  c(n = nrow(x), evaluated = nrow(y), tp = tp, fp = fp, fn = fn, tn = tn,
    precision = ratio(tp, tp + fp), recall = ratio(tp, tp + fn),
    f1 = ratio(2 * tp, 2 * tp + fp + fn), fpr = ratio(fp, fp + tn),
    fnr = ratio(fn, fn + tp), unknown_partial_rate = mean(x$status != "COMPLETE"),
    coverage = mean(x$status == "COMPLETE"))
}
bootstrap_ci <- function(x, statistic, iterations = 2000, seed = 20261122) {
  if (!nrow(x)) return(c(lower = NA_real_, upper = NA_real_, valid = 0))
  set.seed(seed)
  values <- replicate(iterations, statistic(x[sample.int(nrow(x), nrow(x), replace = TRUE), , drop = FALSE]))
  values <- values[is.finite(values)]
  if (length(values) < iterations * .95) return(c(lower = NA_real_, upper = NA_real_, valid = length(values)))
  c(lower = unname(quantile(values, .025)), upper = unname(quantile(values, .975)), valid = length(values))
}
validate_accuracy <- function(x) {
  for (field in c("case_id", "configuration", "status"))
    if (anyNA(x[[field]]) || any(!nzchar(trimws(x[[field]])))) stop("Missing ", field)
  if (any(!x$status %in% c("COMPLETE", "PARTIAL", "UNKNOWN"))) stop("Invalid status")
  for (field in c("prediction", "ground_truth"))
    if (any(!is.na(x[[field]]) & !x[[field]] %in% c(0, 1))) stop("Invalid ", field)
  if (anyDuplicated(x[c("case_id", "configuration")])) stop("Duplicate case/configuration")
  disagreements <- vapply(split(x$ground_truth, x$case_id), function(z) length(unique(z[!is.na(z)])) > 1, logical(1))
  if (any(disagreements)) stop("Conflicting ground truth across configurations")
  x
}
paired_difference <- function(x, value, baseline, comparison, iterations = 2000) {
  a <- x[x$configuration == baseline, c("case_id", value), drop = FALSE]
  b <- x[x$configuration == comparison, c("case_id", value), drop = FALSE]
  if (anyDuplicated(a$case_id) || anyDuplicated(b$case_id)) stop("Duplicate paired case IDs")
  names(a)[2] <- "a"; names(b)[2] <- "b"
  joined <- merge(a, b, by = "case_id")
  joined <- joined[complete.cases(joined), , drop = FALSE]
  if (!nrow(joined)) return(data.frame(baseline, comparison, pairs = 0, difference = NA_real_, lower = NA_real_, upper = NA_real_, standardized_effect = NA_real_))
  delta <- joined$b - joined$a
  ci <- bootstrap_ci(data.frame(delta), function(z) mean(z$delta), iterations)
  sd_delta <- sd(delta)
  data.frame(baseline, comparison, pairs = length(delta), difference = mean(delta), lower = ci[1], upper = ci[2], standardized_effect = if (is.na(sd_delta) || sd_delta == 0) NA_real_ else mean(delta) / sd_delta, row.names = NULL)
}
output_dir <- function(args, default) {
  out <- if (length(args) >= 2) args[2] else default
  dir.create(out, recursive = TRUE, showWarnings = FALSE)
  out
}
