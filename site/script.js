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
