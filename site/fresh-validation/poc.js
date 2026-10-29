const numberFormat = new Intl.NumberFormat("en-US");
const root = document.documentElement;
const themeToggle = document.querySelector("#theme-toggle");
const themeMeta = document.querySelector('meta[name="theme-color"]');
let reportData = null;

function node(tag, className = "", text = "") {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== "") item.textContent = text;
  return item;
}

function safeGitHubUrl(value) {
  try {
    const parsed = new URL(value, window.location.href);
    if (parsed.protocol === "https:" && parsed.hostname.toLowerCase() === "github.com" && !parsed.username && !parsed.password) {
      return parsed.href;
    }
  } catch {
    return null;
  }
  return null;
}

function externalAnchor(label, value, className = "") {
  const link = node("a", className, label);
  const href = safeGitHubUrl(value);
  if (!href) {
    link.setAttribute("aria-disabled", "true");
    return link;
  }
  link.href = href;
  link.target = "_blank";
  link.rel = "noreferrer";
  return link;
}

function syncTheme() {
  const dark = root.dataset.theme === "dark";
  const label = themeToggle?.querySelector(".theme-toggle-label");
  themeToggle?.setAttribute("aria-pressed", String(dark));
  themeToggle?.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  themeToggle?.setAttribute("title", dark ? "Switch to light mode" : "Switch to dark mode");
  if (label) label.textContent = dark ? "Light mode" : "Dark mode";
  if (themeMeta) themeMeta.content = dark ? "#111417" : "#ffffff";
}

syncTheme();
themeToggle?.addEventListener("click", () => {
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  try {
    localStorage.setItem("vigil-fuse-theme", root.dataset.theme);
  } catch {
    // Theme remains available for the current page view.
  }
  syncTheme();
});

function renderMetrics(data) {
  const totals = data.totals;
  const partialRepositoryCount = data.repositories.filter((repo) => repo.scanStatus === "partial").length;
  const metrics = [
    [totals.finding_count, "raw signals"],
    [totals.repository_count, "repositories"],
    [totals.files_scanned, "files scanned"],
    [partialRepositoryCount, partialRepositoryCount === 1 ? "partial repository" : "partial repositories"]
  ];
  const container = document.querySelector("#report-metrics");
  container.replaceChildren(...metrics.map(([value, label]) => {
    const metric = node("div", "report-metric");
    metric.append(node("span", "", label), node("strong", "", numberFormat.format(value)));
    return metric;
  }));

  const severity = data.severityCounts;
  const severityLine = document.querySelector("#report-severity");
  severityLine.replaceChildren(node("strong", "", "Severity"));
  for (const [key, label] of [["high", "high"], ["medium", "medium"], ["info", "informational"]]) {
    const item = node("span", "severity-item", "");
    item.dataset.severity = key;
    item.append(node("b", "", numberFormat.format(severity[key] ?? 0)), document.createTextNode(label));
    severityLine.append(item);
  }
}

function renderLead(data) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const finding = [...data.findings]
    .sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
      || a.repository.localeCompare(b.repository)
      || a.file.localeCompare(b.file)
      || a.line - b.line)[0];
  const container = document.querySelector("#signal-lead");
  if (!finding) {
    container.replaceChildren(node("p", "report-empty", "No finding signals were recorded in this run."));
    return;
  }
  const content = node("div", "lead-content");
  content.append(
    node("span", "lead-label", "Example high-severity signal"),
    node("span", "lead-meta", `${finding.ruleId} / ${finding.severity} severity / ${finding.confidence} confidence`),
    externalAnchor(finding.title, finding.sourceUrl, "lead-title"),
    node("span", "lead-source", `${finding.repository} / ${finding.file}:${finding.line}`),
    node("small", "lead-limit", "Static evidence only. Runtime use is not established.")
  );
  container.replaceChildren(content);
}

function renderBarChart(container, rows, labelFor, valueFor) {
  const maxValue = Math.max(1, ...rows.map(valueFor));
  container.replaceChildren();
  for (const item of rows) {
    const value = valueFor(item);
    const row = node("div", "report-bar-row");
    const label = node("span", "report-bar-label", labelFor(item));
    const track = node("span", "report-bar-track");
    track.setAttribute("aria-hidden", "true");
    const fill = node("span", "report-bar-fill");
    fill.style.setProperty("--bar-width", `${value === 0 ? 0 : Math.max(1, value / maxValue * 100)}%`);
    track.append(fill);
    const count = node("strong", "report-bar-value", numberFormat.format(value));
    row.setAttribute("aria-label", `${labelFor(item)}: ${numberFormat.format(value)} raw signals`);
    row.append(label, track, count);
    container.append(row);
  }
}

function renderCoverage(data) {
  const totals = data.totals;
  const modules = totals.module_coverage || {};
  const firmware = modules.firmware_candidates || {};
  const actions = modules.github_actions || {};
  const pio = modules.platformio || {};
  const netlist = modules.hardware_netlist || {};
  const decoding = modules.source_decoding || {};
  const extensionText = Object.entries(firmware.extension_counts || {})
    .map(([extension, count]) => `${extension} ${numberFormat.format(count)}`)
    .join(", ") || "none found";
  const hardwareText = Object.entries(totals.hardware_category_counts || {})
    .map(([category, count]) => `${numberFormat.format(count)} ${category}`)
    .join(", ") || "none found";
  const rows = [
    ["PlatformIO environments", `${numberFormat.format(pio.environment_count || 0)} across ${numberFormat.format(pio.configuration_count || 0)} configs; ${numberFormat.format(pio.partial_scope_count || 0)} partial scope`],
    ["Legacy text decoding", `${numberFormat.format(decoding.fallback_file_count || 0)} ${decoding.fallback_file_count === 1 ? "file" : "files"} decoded with ${decoding.fallback_encoding || "fallback encoding"}`],
    ["Firmware filename candidates", `${numberFormat.format(firmware.candidate_count || 0)}; ${extensionText}; bytes not inspected`],
    ["Hardware filename matches", `${numberFormat.format(totals.hardware_file_count || 0)}; ${hardwareText}; no design review`],
    ["GitHub Actions workflows", `${numberFormat.format(actions.workflow_count || 0)} files; ${numberFormat.format(actions.non_sha_action_reference_count || 0)} non-SHA refs`],
    ["Floating Action branches", `${numberFormat.format(actions.floating_branch_reference_count || 0)} references; ${numberFormat.format(actions.finding_count || 0)} informational signals`],
    ["Parsed hardware netlists", `${numberFormat.format(netlist.scope_count || 0)} scopes; ${numberFormat.format(netlist.component_count || 0)} components; ${numberFormat.format(netlist.net_count || 0)} nets`]
  ];
  const list = document.querySelector("#coverage-list");
  list.replaceChildren(...rows.map(([label, value]) => {
    const row = node("div");
    row.append(node("dt", "", label), node("dd", "", value));
    return row;
  }));
}

function renderTriage(data) {
  const rules = data.ruleCounts || {};
  const placeholders = data.noiseReduction?.filteredPlaceholderCount || 0;
  const hasBaselineTriage = (data.noiseReduction?.baselineSignalCount || 0) > 0;
  const triage = data.triageSummary || {};
  const reviewed = triage.signalCount || 0;
  const setText = (selector, text) => {
    const element = document.querySelector(selector);
    if (element) element.textContent = text;
  };
  setText(
    "#triage-fuse001",
    `${numberFormat.format(rules.FUSE001 || 0)} credential-like signals remain for review. ${hasBaselineTriage ? `The prior regression corpus had ${numberFormat.format(placeholders)} narrow tutorial-placeholder matches excluded by fixture-backed patterns.` : "No placeholder-baseline comparison is attached to this independent scan."} Remaining matches may still be examples or defaults.`
  );
  setText(
    "#triage-fuse002",
    `${numberFormat.format(rules.FUSE002 || 0)} private-key marker signals identify files for review. A marker does not establish that key material is active or shipped.`
  );
  setText(
    "#triage-fuse003",
    `${numberFormat.format(rules.FUSE003 || 0)} TLS verification-bypass indicators remain for call-path and build review. Static matching does not prove runtime reachability.`
  );

  const partialScopes = data.repositories.flatMap((repo) => repo.scopes || [])
    .filter((scope) => scope.status === "partial").length;
  const totalScopes = data.totals.scan_scope_count || 0;
  const partialModules = data.totals.module_coverage?.platformio?.partial_scope_count || 0;
  setText(
    "#snapshot-status-note",
    `Each source link opens the exact commit FUSE scanned. ${numberFormat.format(partialScopes)} of ${numberFormat.format(totalScopes)} ${totalScopes === 1 ? "scope" : "scopes"} ${partialScopes === 1 ? "is" : "are"} marked partial.`
  );
  setText(
    "#cohort-limit",
    data.meta.interpretation || "Static signals require human review and do not confirm vulnerabilities."
  );
  const decoding = data.totals.module_coverage?.source_decoding || {};
  setText(
    "#coverage-limit",
    `${numberFormat.format(data.totals.files_skipped || 0)} selected ${data.totals.files_skipped === 1 ? "file was" : "files were"} skipped. ${numberFormat.format(decoding.fallback_file_count || 0)} legacy text ${decoding.fallback_file_count === 1 ? "file used" : "files used"} ${decoding.fallback_encoding || "fallback"} decoding, recorded in report coverage metadata.`
  );
  setText(
    "#partial-module-limit",
    partialModules
      ? `${numberFormat.format(partialModules)} ${partialModules === 1 ? "scope has" : "scopes have"} partial PlatformIO context because optional configuration includes are absent from the pinned checkout. Source scan status is reported separately.`
      : "No partial PlatformIO context was detected. Source-level scan status is reported separately and can be partial when selected files are skipped."
  );
  const overlapNote = document.querySelector("#snapshot-overlap-limit");
  if (overlapNote) {
    overlapNote.textContent = data.meta.cohort === "regression-validation"
      ? "IoTGoat includes OpenWrt source that is also present in the separate OpenWrt snapshot. Raw scope totals are not deduplicated."
      : "Counts are raw per repository snapshot and are not deduplicated across repositories.";
  }
  const triageHeading = document.querySelector("#triage-title");
  if (triageHeading && reviewed) {
    triageHeading.textContent = `Next steps for ${numberFormat.format(reviewed)} ${reviewed === 1 ? "signal" : "signals"}`;
  }
}

function renderRepositories(data) {
  const tbody = document.querySelector("#repository-list");
  const repoFilter = document.querySelector("#repository-filter");
  const rows = data.repositories.map((repo) => {
    const tr = node("tr");
    const nameCell = node("td");
    nameCell.dataset.label = "Repository";
    nameCell.append(externalAnchor(repo.name, `${repo.url}/tree/${repo.commit}`, "repository-name"));

    const commitCell = node("td");
    commitCell.dataset.label = "Commit";
    commitCell.append(externalAnchor(repo.commit.slice(0, 12), `${repo.url}/tree/${repo.commit}`, "commit-link"));

    const statusCell = node("td", "status-text", repo.scanStatus);
    statusCell.dataset.label = "Status";
    statusCell.dataset.status = repo.scanStatus;

    const filesCell = node("td", "numeric-cell", numberFormat.format(repo.filesScanned));
    filesCell.dataset.label = "Files scanned";
    const findingsCell = node("td", "numeric-cell", numberFormat.format(repo.findingCount));
    findingsCell.dataset.label = "Signals";
    tr.append(nameCell, commitCell, statusCell, filesCell, findingsCell);
    return tr;
  });
  tbody.replaceChildren(...rows);

  const options = [node("option", "", "All repositories")];
  options[0].value = "";
  for (const repo of data.repositories) {
    const option = node("option", "", repo.name);
    option.value = repo.id;
    options.push(option);
  }
  repoFilter.replaceChildren(...options);
}

function renderFindings(data) {
  const search = document.querySelector("#finding-search");
  const ruleFilter = document.querySelector("#rule-filter");
  const severityFilter = document.querySelector("#severity-filter");
  const repositoryFilter = document.querySelector("#repository-filter");
  const filterPanel = document.querySelector("#finding-filter-panel");
  const tbody = document.querySelector("#finding-list");
  const count = document.querySelector("#finding-result-count");

  const addOptions = (select, values, label) => {
    const options = [node("option", "", label)];
    options[0].value = "";
    for (const value of values) {
      const option = node("option", "", value);
      option.value = value;
      options.push(option);
    }
    select.replaceChildren(...options);
  };
  addOptions(ruleFilter, [...new Set(data.findings.map((finding) => finding.ruleId))].sort(), "All rules");
  addOptions(severityFilter, [...new Set(data.findings.map((finding) => finding.severity))].sort(), "All severities");
  if (window.matchMedia("(max-width: 640px)").matches) filterPanel.open = false;

  const applyFilters = () => {
    const query = search.value.trim().toLocaleLowerCase();
    const rule = ruleFilter.value;
    const severity = severityFilter.value;
    const repository = repositoryFilter.value;
    const visible = data.findings.filter((finding) => {
      const searchable = `${finding.repository} ${finding.file} ${finding.title} ${finding.ruleId}`.toLocaleLowerCase();
      return (!query || searchable.includes(query))
        && (!rule || finding.ruleId === rule)
        && (!severity || finding.severity === severity)
        && (!repository || finding.repositoryId === repository);
    });
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
    visible.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
      || a.repository.localeCompare(b.repository)
      || a.file.localeCompare(b.file)
      || a.line - b.line);
    count.textContent = `${numberFormat.format(visible.length)} of ${numberFormat.format(data.findings.length)} raw signals`;
    if (!visible.length) {
      const row = node("tr");
      const cell = node("td", "report-empty", "No signals match these filters.");
      cell.colSpan = 4;
      row.append(cell);
      tbody.replaceChildren(row);
      return;
    }
    tbody.replaceChildren(...visible.map((finding) => {
      const row = node("tr");
      const sourceCell = node("td");
      sourceCell.dataset.label = "Source and finding";
      sourceCell.append(externalAnchor(`${finding.file}:${finding.line}`, finding.sourceUrl, "source-link"));
      sourceCell.append(node("span", "finding-title", finding.title));

      const ruleCell = node("td", "rule-id", finding.ruleId);
      ruleCell.dataset.label = "Rule";
      const severityCell = node("td", "", finding.severity);
      severityCell.dataset.label = "Severity";
      severityCell.dataset.severity = finding.severity;
      const confidenceCell = node("td", "confidence-value", finding.confidence);
      confidenceCell.dataset.label = "Confidence";
      row.append(sourceCell, ruleCell, severityCell, confidenceCell);
      return row;
    }));
  };

  [search, ruleFilter, severityFilter, repositoryFilter].forEach((control) => {
    control.addEventListener("input", applyFilters);
    control.addEventListener("change", applyFilters);
  });
  document.querySelector("#filter-reset").addEventListener("click", () => {
    search.value = "";
    ruleFilter.value = "";
    severityFilter.value = "";
    repositoryFilter.value = "";
    applyFilters();
    search.focus();
  });
  applyFilters();
}

function renderReport(data) {
  const date = new Date(`${data.meta.scanDate}T00:00:00Z`);
  const dateLabel = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }).format(date);
  const isRegression = data.meta.cohort === "regression-validation";
  document.querySelector("#report-date").textContent = isRegression ? "Pinned regression run" : "Independent holdout run";
  document.querySelector("#cohort-label").textContent = isRegression ? "Regression validation" : "Independent validation";
  document.querySelector("#cohort-description").textContent = data.meta.interpretation || "Static signals require human review.";
  document.querySelector("#report-footer-note").textContent = `Local proof of concept, generated from the ${dateLabel} ${isRegression ? "regression" : "independent validation"} run.`;
  const fuse = data.meta.fuse || {};
  document.querySelector("#report-provenance").textContent = `FUSE ${fuse.version || "unknown"} / ${String(fuse.commit || "unknown").slice(0, 12)} / ${dateLabel}`;
  renderMetrics(data);
  renderLead(data);
  renderTriage(data);
  renderCoverage(data);
  const positiveRepos = [...data.repositories]
    .filter((repo) => repo.findingCount > 0)
    .sort((a, b) => b.findingCount - a.findingCount || a.name.localeCompare(b.name));
  const zeroRepos = data.repositories.length - positiveRepos.length;
  const repoBars = zeroRepos
    ? [...positiveRepos, { name: `${numberFormat.format(zeroRepos)} repositories with zero signals`, findingCount: 0 }]
    : positiveRepos;
  renderBarChart(document.querySelector("#repository-chart"), repoBars, (repo) => repo.name, (repo) => repo.findingCount);
  const ruleRows = Object.entries(data.ruleCounts).map(([id, count]) => ({ id, count }));
  renderBarChart(document.querySelector("#rule-chart"), ruleRows, (rule) => rule.id, (rule) => rule.count);
  renderRepositories(data);
  renderFindings(data);
}

function showLoadError(error) {
  const message = `The local report data could not be loaded. ${error.message || "Check that this page is served with data.json."}`;
  for (const id of ["report-metrics", "repository-chart", "rule-chart", "coverage-list", "repository-list", "finding-list"]) {
    const target = document.getElementById(id);
    if (target) target.replaceChildren(node("p", "report-empty", message));
  }
  document.querySelector("#finding-result-count").textContent = "Report data unavailable";
}

fetch("data.json", { cache: "no-store" })
  .then((response) => {
    if (!response.ok) throw new Error(`Request failed with status ${response.status}.`);
    return response.json();
  })
  .then((data) => {
    reportData = data;
    renderReport(reportData);
  })
  .catch(showLoadError);
