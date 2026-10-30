const themeToggle = document.querySelector("#theme-toggle");
const themeMeta = document.querySelector('meta[name="theme-color"]');
const root = document.documentElement;

function syncThemeControl() {
  const isDark = root.dataset.theme === "dark";
  const action = isDark ? "Switch to light mode" : "Switch to dark mode";
  const label = themeToggle?.querySelector(".theme-toggle-label");
  themeToggle?.setAttribute("aria-pressed", String(isDark));
  themeToggle?.setAttribute("aria-label", action);
  themeToggle?.setAttribute("title", action);
  if (label) label.textContent = isDark ? "Light mode" : "Dark mode";
  if (themeMeta) themeMeta.content = isDark ? "#111417" : "#ffffff";
}

syncThemeControl();
themeToggle?.addEventListener("click", () => {
  const nextTheme = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = nextTheme;
  try {
    localStorage.setItem("vigil-fuse-theme", nextTheme);
  } catch {
    // The toggle still works for this page view when storage is unavailable.
  }
  syncThemeControl();
});

const examples = {
  tls: {
    rule: "FUSE003",
    category: "transport security",
    title: "TLS peer verification appears disabled",
    location: "tests/fixtures/rules/FUSE003-vulnerable.fixture:1",
    evidence: "verify=False",
    severity: "High",
    confidence: "High",
    explanation: "An explicit TLS verification bypass appears in the source. FUSE cannot establish whether this code path runs.",
    remediation: "Enable certificate-chain and hostname verification; keep any test override out of release builds."
  },
  secret: {
    rule: "FUSE001",
    category: "secrets",
    title: "Credential-like literal assigned in source",
    location: "tests/fixtures/rules/FUSE001-vulnerable.fixture:2",
    evidence: 'mqtt_password: "[REDACTED]"',
    severity: "Medium",
    confidence: "High",
    explanation: "A credential-related name is assigned a literal value. FUSE cannot determine whether it is valid or used.",
    remediation: "Remove and rotate an exposed value; provision secrets through a protected device workflow."
  },
  boot: {
    rule: "FUSE006",
    category: "boot integrity",
    title: "ESP-IDF bootloader image validation is disabled",
    location: "tests/fixtures/rules/FUSE006-vulnerable.fixture:1",
    evidence: "CONFIG_BOOTLOADER_SKIP_VALIDATE_ALWAYS=y",
    severity: "Medium",
    confidence: "High",
    explanation: "The scanned Kconfig-style input skips app-image validation. This does not prove the file is active in the release build.",
    remediation: "Unset the setting unless a reviewed requirement justifies it; verify the effective release configuration."
  }
};

const demoFields = {
  rule: document.querySelector("#demo-rule"),
  title: document.querySelector("#demo-title"),
  location: document.querySelector("#demo-location"),
  evidence: document.querySelector("#demo-evidence"),
  severity: document.querySelector("#demo-severity"),
  confidence: document.querySelector("#demo-confidence"),
  explanation: document.querySelector("#demo-explanation"),
  remediation: document.querySelector("#demo-remediation")
};

const demoButtons = [...document.querySelectorAll(".demo-switch")];

function selectExample(key, trigger) {
  const example = examples[key];
  if (!example) return;

  demoFields.rule.replaceChildren(document.createTextNode(example.rule + " "));
  const category = document.createElement("span");
  category.textContent = example.category;
  demoFields.rule.append(category);
  demoFields.title.textContent = example.title;
  demoFields.location.textContent = example.location;
  demoFields.evidence.textContent = example.evidence;
  demoFields.severity.textContent = example.severity;
  demoFields.confidence.textContent = example.confidence;
  demoFields.explanation.textContent = example.explanation;
  demoFields.remediation.textContent = example.remediation;
  document.querySelector(".finding-demo").setAttribute("aria-label", example.rule + " vulnerable test fixture");

  demoButtons.forEach((button) => {
    const selected = button === trigger;
    button.classList.toggle("is-selected", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
}

demoButtons.forEach((button) => {
  button.addEventListener("click", () => selectExample(button.dataset.example, button));
});

const copyButton = document.querySelector("#copy-command");
const commandNode = document.querySelector("#scan-command");

copyButton?.addEventListener("click", async () => {
  const originalLabel = "Copy";
  try {
    await navigator.clipboard.writeText(commandNode.textContent.trim());
    copyButton.textContent = "Copied";
    copyButton.setAttribute("aria-label", "Scan command copied");
  } catch {
    copyButton.textContent = "Select command";
    copyButton.setAttribute("aria-label", "Select and copy the scan command");
  }
  window.setTimeout(() => {
    copyButton.textContent = originalLabel;
    copyButton.setAttribute("aria-label", "Copy the generic scan command");
  }, 1800);
});

const showcase = document.querySelector("#showcase-track");
document.querySelectorAll(".carousel-button").forEach((button) => {
  button.addEventListener("click", () => {
    const direction = button.dataset.scroll === "back" ? -1 : 1;
    const slide = showcase?.querySelector(".showcase-slide");
    if (!showcase || !slide) return;
    const gap = Number.parseFloat(getComputedStyle(showcase).columnGap) || 0;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    showcase.scrollBy({ left: direction * (slide.getBoundingClientRect().width + gap), behavior: reduceMotion ? "auto" : "smooth" });
  });
});

const numberFormat = new Intl.NumberFormat("en-US");

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function externalLink(label, href, className = "") {
  const link = element("a", className, label);
  let parsed;
  try {
    parsed = new URL(href, window.location.href);
  } catch {
    parsed = null;
  }
  if (
    !parsed
    || parsed.protocol !== "https:"
    || parsed.hostname.toLowerCase() !== "github.com"
    || parsed.username
    || parsed.password
  ) {
    link.setAttribute("aria-disabled", "true");
    link.title = "Link omitted because it is not an approved HTTPS GitHub URL.";
    return link;
  }
  link.href = parsed.href;
  link.target = "_blank";
  link.rel = "noreferrer";
  return link;
}

function renderScanMetrics(data) {
  const root = document.querySelector("#scan-metrics");
  if (!root) return;
  const totals = data.totals;
  const repositoryCount = document.querySelector("#repo-snapshot-count");
  if (repositoryCount) repositoryCount.textContent = numberFormat.format(totals.repository_count);
  const scanIntro = document.querySelector("#scan-intro");
  if (scanIntro && /^\d{4}-\d{2}-\d{2}$/.test(data.scan_date || "")) {
    const date = new Date(`${data.scan_date}T00:00:00Z`);
    const formattedDate = new Intl.DateTimeFormat("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
      timeZone: "UTC"
    }).format(date);
    scanIntro.textContent = `Snapshot collected ${formattedDate}. It spans embedded and IoT repositories. Signals are static review leads, not confirmed vulnerabilities.`;
  }
  const severityCounts = document.querySelector("#scan-severity-counts");
  if (severityCounts) severityCounts.textContent = `${numberFormat.format(totals.severity_counts.high)} high · ${numberFormat.format(totals.severity_counts.medium)} medium`;
  const metrics = [
    [numberFormat.format(totals.finding_count), "raw FUSE signals"],
    [numberFormat.format(totals.repository_count), "repository snapshots"],
    [numberFormat.format(totals.files_scanned), "supported files scanned"],
    [numberFormat.format(totals.files_skipped), "files skipped by scanner"],
    [numberFormat.format(totals.hardware_file_count || 0), "hardware artifacts inventoried"]
  ];
  root.replaceChildren(...metrics.map(([value, label]) => {
    const item = element("div", "scan-metric");
    item.append(element("strong", "", value), element("span", "", label));
    return item;
  }));
}

function renderScanChart(container, rows, labelFor, maxValue) {
  if (!container) return;
  const denominator = Math.log10(maxValue + 1) || 1;
  const chartRows = rows.map((item) => {
    const row = element("div", "scan-chart-row");
    const label = labelFor(item);
    if (label instanceof Node) row.append(label);
    else row.append(element("span", "scan-bar-label", label));

    const track = element("span", "scan-bar-track");
    track.setAttribute("aria-hidden", "true");
    const bar = element("span", "scan-bar");
    const value = Number(item.finding_count ?? item.count ?? 0);
    const width = value > 0 ? Math.max(1, (Math.log10(value + 1) / denominator) * 100) : 0;
    bar.style.setProperty("--bar-width", `${width}%`);
    track.append(bar);
    row.append(track, element("strong", "scan-bar-count", numberFormat.format(value)));
    return row;
  });

  const axisRow = element("div", "scan-axis-row");
  axisRow.append(element("span", "", ""));
  const axis = element("div", "scan-axis");
  axis.setAttribute("aria-hidden", "true");
  const ticks = [1, 10, 100, 1000].filter((tick) => tick <= maxValue);
  const finalTick = ticks.at(-1) ?? 0;
  if (maxValue > finalTick) {
    const gap = Math.log10(maxValue + 1) / denominator - Math.log10(finalTick + 1) / denominator;
    if (gap >= 0.12) ticks.push(maxValue);
  }
  ticks.forEach((tick) => {
    const label = element("span", "", numberFormat.format(tick));
    label.style.left = `${(Math.log10(tick + 1) / denominator) * 100}%`;
    axis.append(label);
  });
  axisRow.append(axis, element("span", "", ""));

  const note = element("p", "scan-chart-note", "Bar length uses a logarithmic scale. Exact raw counts appear at right.");
  container.replaceChildren(...chartRows, axisRow, note);
}

function renderRepositoryDetails(data) {
  const list = document.querySelector("#repository-list");
  if (!list) return;
  const repos = data.repositories;
  const sorted = [...repos].sort((a, b) => b.finding_count - a.finding_count);
  list.replaceChildren(...sorted.map((repo, index) => {
    const details = element("details", "scan-repository");
    details.id = `repo-${repo.id}`;
    const summary = element("summary");
    const identity = element("span", "scan-repo-identity");
    identity.append(element("small", "", `Repository ${index + 1}`));
    identity.append(element("strong", "", repo.name));
    summary.append(identity, element("span", "scan-profile", repo.profile));
    const count = element("span", "scan-signal-count");
    count.append(element("strong", "", numberFormat.format(repo.finding_count)), element("small", "", "raw signals"));
    summary.append(count);
    details.append(summary);

    const body = element("div", "scan-repo-content");
    const meta = element("p", "scan-repo-meta");
    meta.append(
      element("span", "", `${numberFormat.format(repo.files_scanned)} files scanned`),
      element("span", "", `${numberFormat.format(repo.severity_counts.high)} high severity labels`),
      element("span", "", `${numberFormat.format(repo.severity_counts.medium)} medium severity labels`),
      element("span", "", `${numberFormat.format(repo.hardware_file_count || 0)} hardware artifacts inventoried`)
    );
    body.append(meta);

    const scopes = element("ul", "scan-scopes");
    repo.scopes.forEach((scope) => {
      const item = element("li", "scan-scope");
      const hardware = scope.hardware_inventory || {};
      const hardwareCategories = Object.entries(hardware.category_counts || {})
        .map(([category, count]) => `${numberFormat.format(count)} ${category}`)
        .join(" · ");
      const hardwareLabel = hardware.file_count
        ? `${numberFormat.format(hardware.file_count)} hardware artifacts${hardwareCategories ? ` · ${hardwareCategories}` : ""}`
        : `No recognized hardware artifacts${hardware.complete ? "" : " · inventory partial"}`;
      item.append(
        element("p", "", scope.scope),
        element(
          "small",
          "",
          `${scope.profile} profile · ${numberFormat.format(scope.files_scanned)} files · ${numberFormat.format(scope.finding_count)} signals · ${scope.scan_status || "status unavailable"} scan · ${scope.support_label || "support unlabelled"}`
        ),
        element("small", "", hardwareLabel)
      );
      scopes.append(item);
    });
    body.append(scopes);

    if (repo.finding_groups.length) {
      const groups = element("div", "scan-groups");
      repo.finding_groups.forEach((group) => {
        const card = element("article", "scan-group");
        const heading = element("div", "scan-group-heading");
        heading.append(element("code", "", group.rule_id), element("strong", "", group.title));
        card.append(heading);
        const confidence = Object.entries(group.confidence_counts)
          .map(([rating, total]) => `${rating} confidence: ${numberFormat.format(total)}`)
          .join(" · ");
        card.append(element("p", "scan-group-count", `${numberFormat.format(group.count)} signals · ${group.severity} severity · ${confidence}`));

        const examples = element("ul", "scan-examples");
        group.examples.forEach((example) => {
          const encodedPath = example.file.split("/").map(encodeURIComponent).join("/");
          const line = example.line ? `#L${example.line}` : "";
          const path = `${example.file}${example.line ? `:${example.line}` : ""}`;
          const exampleLink = externalLink("", `${repo.url}/blob/${repo.commit}/${encodedPath}${line}`);
          exampleLink.append(element("code", "", path));
          examples.append(element("li", "").appendChild(exampleLink));
        });
        card.append(examples);
        groups.append(card);
      });
      body.append(groups);
    } else {
      body.append(element("p", "scan-empty", "No rule matches in the scanned sample. This result describes only the listed files and enabled rules."));
    }

    const links = element("div", "scan-repo-links");
    links.append(
      externalLink("Source repository ↗", repo.url),
      externalLink(`Pinned source commit ${repo.commit.slice(0, 10)} ↗`, `${repo.url}/commit/${repo.commit}`)
    );
    body.append(links);

    const reportLinks = element("div", "scan-report-links");
    repo.scopes.forEach((scope) => {
      const prefix = repo.scopes.length > 1 ? `${scope.id}: ` : "";
      reportLinks.append(
        externalLink(`${prefix}JSON report ↗`, scope.report_files.github_json),
        externalLink(`${prefix}text report ↗`, scope.report_files.github_text),
        externalLink(`${prefix}SARIF report ↗`, scope.report_files.github_sarif)
      );
    });
    body.append(reportLinks);
    details.append(body);
    return details;
  }));
}

function renderSupportMatrix(data) {
  const list = document.querySelector("#support-list");
  const legend = document.querySelector("#support-legend");
  if (!list || !Array.isArray(data.capabilities) || !data.labels || typeof data.labels !== "object") return;

  const usedLabels = [...new Set(data.capabilities.map((capability) => capability.label))]
    .filter((label) => typeof label === "string" && data.labels[label]);
  if (legend) {
    legend.replaceChildren(...usedLabels.map((label) => {
      const entry = element("div", "");
      entry.append(element("dt", "", label[0].toUpperCase() + label.slice(1)));
      entry.append(element("dd", "", data.labels[label]));
      return entry;
    }));
  }

  const entries = data.capabilities.map((capability) => {
    const details = element("details", "support-entry");
    const summary = element("summary", "support-entry-summary");
    const identity = element("span", "support-entry-identity");
    identity.append(element("strong", "", capability.input || "Unspecified input"));
    identity.append(element("code", "support-entry-id", capability.id || "unknown"));
    summary.append(identity);

    const scope = element("span", "support-entry-scope", capability.scope || "Scope not documented.");
    summary.append(scope);
    const knownLabels = ["basic", "supported", "partial", "experimental", "detected", "planned", "unsupported"];
    const status = knownLabels.includes(capability.label) ? capability.label : "unknown";
    summary.append(element("span", `support-status support-status-${status}`, status));
    summary.append(element("span", "support-entry-caret", "＋"));
    details.append(summary);

    const body = element("div", "support-entry-details");
    const limitations = Array.isArray(capability.limitations) ? capability.limitations : [];
    body.append(element("strong", "", "Limits"));
    if (limitations.length) {
      const listNode = element("ul", "");
      limitations.forEach((limitation) => listNode.append(element("li", "", String(limitation))));
      body.append(listNode);
    } else {
      body.append(element("p", "", "No additional limitations recorded."));
    }
    details.append(body);
    details.addEventListener("toggle", () => {
      const caret = details.querySelector(".support-entry-caret");
      if (caret) caret.textContent = details.open ? "−" : "＋";
    });
    return details;
  });
  list.replaceChildren(...entries);
}

async function loadSupportMatrix() {
  try {
    const response = await fetch("data/support-matrix.json", { cache: "no-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderSupportMatrix(await response.json());
  } catch {
    const list = document.querySelector("#support-list");
    if (list) list.replaceChildren(element("p", "scan-empty", "The capability matrix could not be loaded. The support limits remain documented in the repository."));
  }
}

async function loadRepositoryScanResults() {
  try {
    const response = await fetch("data/repository-scan-results.json", { cache: "no-cache" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderScanMetrics(data);
    const repositories = [...data.repositories].sort((a, b) => b.finding_count - a.finding_count);
    renderScanChart(
      document.querySelector("#repository-chart"),
      repositories,
      (repo) => {
        const label = element("a", "scan-bar-label", repo.name);
        label.href = `#repo-${repo.id}`;
        return label;
      },
      Math.max(1, ...repositories.map((repo) => repo.finding_count))
    );
    const rules = Object.entries(data.totals.rule_counts).map(([rule_id, count]) => ({ rule_id, count }));
    renderScanChart(
      document.querySelector("#rule-chart"),
      rules,
      (rule) => rule.rule_id,
      Math.max(1, ...rules.map((rule) => rule.count))
    );
    renderRepositoryDetails(data);
  } catch (error) {
    const list = document.querySelector("#repository-list");
    if (list) list.replaceChildren(element("p", "scan-empty", "The published scan summary could not be loaded. The detailed report files remain available in the FUSE repository."));
  }
}

loadRepositoryScanResults();
loadSupportMatrix();

const revealItems = document.querySelectorAll(".reveal, .workflow-step, .rule-table tbody tr, .boundary-columns p");
if ("IntersectionObserver" in window) {
  const revealObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach((entry) => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add("is-visible");
      observer.unobserve(entry.target);
    });
  }, { threshold: 0.12 });
  revealItems.forEach((item) => revealObserver.observe(item));
} else {
  revealItems.forEach((item) => item.classList.add("is-visible"));
}
