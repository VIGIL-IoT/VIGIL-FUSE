import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as k from "./vendor/anatomy/iso-kit.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DOC_FIGURES = resolve(ROOT, "docs/figures");
const SITE_DIAGRAMS = resolve(ROOT, "site/diagrams");
const WIDTH = 900;
const HEIGHT = 500;

/*
Concept: a conceptual review bench that explains FUSE's finding fields, not
physical hardware and not the scanner's implementation. A redacted evidence
card passes beneath a reader. Two independent controls record potential-impact
severity and evidence confidence. An output slip keeps those fields beside
applicability and validation status. The example state mirrors the illustrative
FUSE001 record in docs/finding-schema.md. There is no combined risk score.

Parts list, written before the geometry:
*/
const PARTS = Object.freeze({
  base: [
    "lower chassis plate",
    "upper work surface",
    "four elastomer feet",
    "four foot collars",
    "four countersunk corner screws",
    "perimeter groove",
    "front trim rail",
    "graduated setup strip",
    "fourteen short setup ticks",
  ],
  evidence: [
    "card-tray platform",
    "left tray wall",
    "right tray wall",
    "rear tray wall",
    "evidence card",
    "three printed evidence rules",
    "redaction band",
    "two card registration dots",
    "reader bridge foot plates",
    "two reader uprights",
    "reader crossbeam",
    "reader carriage",
    "lens barrel",
    "barrel knurl",
    "lens rim",
    "aperture ring",
    "dashed scan line",
    "two bridge end caps",
    "four bridge fasteners",
  ],
  severity: [
    "severity gauge pedestal",
    "severity outer shell",
    "knurled severity rim",
    "severity face disc",
    "severity inner scale ring",
    "five ordered severity positions",
    "severity needle",
    "severity pivot cap",
    "unknown-position indicator well",
    "unknown-position indicator",
  ],
  confidence: [
    "confidence gauge pedestal",
    "confidence outer shell",
    "knurled confidence rim",
    "confidence face disc",
    "confidence inner scale ring",
    "three ordered confidence positions",
    "confidence needle",
    "confidence pivot cap",
  ],
  report: [
    "report slip tray",
    "report slip",
    "upper slip clamp",
    "lower slip stop",
    "four report field rules",
    "severity field text",
    "confidence field text",
    "applicability field text",
    "validation field text",
    "four slip fasteners",
  ],
});

const partCount = Object.values(PARTS).flat().length;
if (partCount < 40) throw new Error(`Anatomy Figure needs 40 parts; listed ${partCount}`);

const BASE = { x: -151, y: -64, w: 302, d: 128, r: 8 };
const TRAY = { x: -139, y: -45, w: 68, d: 88, r: 3 };
const EVIDENCE = { x: -133, y: -38, w: 56, d: 72, r: 2 };
const SEVERITY = { x: -27, y: -8, radius: 27.5, z: 10.8 };
const CONFIDENCE = { x: 48, y: -8, radius: 27.5, z: 10.8 };
const REPORT = { x: 101, y: -47, w: 43, d: 88, r: 2.5 };
const REPORT_TOP = 3.8;
const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const CONFIDENCE_ORDER = ["low", "medium", "high"];
const SEVERITY_START = (-2 * Math.PI) / 3;
const SEVERITY_SPAN = (4 * Math.PI) / 3;
const CONFIDENCE_START = -1.42;
const CONFIDENCE_SPAN = 2.84;
const severitySample = 2;
const confidenceSample = 2;

const P = k.fitProjection(
  [
    ...k.boxCorners(BASE, -17, 0),
    ...k.boxCorners(TRAY, 0, 4),
    ...k.boxCorners(EVIDENCE, 4, 5),
    ...k.boxCorners({ x: -139, y: -45, w: 68, d: 6, r: 1 }, 45, 49),
    [-136, -42, 50],
    ...k.boxCorners(REPORT, 2.5, REPORT_TOP),
    [SEVERITY.x, SEVERITY.y, SEVERITY.z + 4],
    [CONFIDENCE.x, CONFIDENCE.y, CONFIDENCE.z + 4],
  ],
  WIDTH,
  HEIGHT,
  { pad: 38, azimuth: 45, elevation: 35 },
);

const S = (paths, style) => k.solidSvg(paths, style);
const L = (path, style) => k.lineSvg(path, style);
const D = (points, style) => k.dotsSvg(points, style);
const at = (point) => k.iso(point, P);

function base() {
  const out = [`<path class="iso-halo" d="${k.haloOf(BASE, -17, 17, P)}"/>`];
  for (const [x, y] of k.corners(BASE, 15)) {
    out.push(S(k.cylinder(x, y, 5, -17, 4, P, 24), { tone: "lo" }));
    out.push(S(k.cylinder(x, y, 3.6, -13, 1, P, 20), { tone: "mid" }));
  }
  out.push(S(k.slabOf(BASE, -12, 12, P, 8, 1.2), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(BASE, 5), 0, P), { tone: "lo" }));
  const screws = k.corners(BASE, 9);
  out.push(L(screws.map(([x, y]) => k.ring(x, y, 2.1, 0, P, 16)).join(""), { tone: "lo" }));
  out.push(D(screws.map(([x, y]) => at([x, y, 0])), { size: 0.48 }));

  const strip = { x: -112, y: 48, w: 224, d: 7, r: 1 };
  out.push(S(k.slabOf(strip, 0, 0.7, P, 3, 0.2), { tone: "lo", crease: "none" }));
  const ticks = k.topTicks(strip.x + 5, strip.x + strip.w - 5, 14, 2, strip.y + 1, 0.7, [1.8, 3.2], P);
  out.push(L(ticks.minor, { tone: "faint" }), L(ticks.major, { tone: "mid" }));
  const rail = { x: -127, y: -56, w: 254, d: 3, r: 0.8 };
  out.push(S(k.slabOf(rail, 0, 1.6, P, 3, 0.3), { tone: "lo" }));
  out.push(L(k.planOutline(k.insetPlan(rail, 0.7), 1.6, P, 3), { tone: "faint" }));
  return out.join("");
}

function evidenceTray() {
  const out = [];
  out.push(S(k.slabOf(TRAY, 0, 4, P, 5, 0.7), { tone: "mid" }));
  const walls = [
    { x: TRAY.x + 1, y: TRAY.y + 3, w: 3, d: TRAY.d - 6, r: 1 },
    { x: TRAY.x + TRAY.w - 4, y: TRAY.y + 3, w: 3, d: TRAY.d - 6, r: 1 },
    { x: TRAY.x + 4, y: TRAY.y + TRAY.d - 6, w: TRAY.w - 8, d: 3, r: 1 },
  ];
  for (const wall of walls) out.push(S(k.slabOf(wall, 4, 4, P, 3, 0.35), { tone: "lo" }));

  out.push(S(k.slabOf(EVIDENCE, 4, 1, P, 5, 0.25), { tone: "hi", crease: "lo" }));
  const rules = [-21, -5, 11].map((y) => k.lineOnTop([EVIDENCE.x + 7, y], [EVIDENCE.x + EVIDENCE.w - 7, y], 5.05, P));
  out.push(L(rules.join(""), { tone: "mid" }));
  const redaction = { x: EVIDENCE.x + 7, y: 17, w: 25, d: 4, r: 0.6 };
  out.push(S(k.slabOf(redaction, 5.05, 0.7, P, 3, 0.15), { tone: "lo", crease: "none" }));
  out.push(D([at([EVIDENCE.x + 3.5, EVIDENCE.y + 4, 5.05]), at([EVIDENCE.x + EVIDENCE.w - 3.5, EVIDENCE.y + 4, 5.05])], { size: 0.4, tone: "lo" }));

  const footPlans = [
    { x: -139, y: -44, w: 5, d: 6, r: 1 },
    { x: -76, y: -44, w: 5, d: 6, r: 1 },
  ];
  for (const plan of footPlans) out.push(S(k.slabOf(plan, 4, 2.5, P, 3, 0.3), { tone: "mid" }));
  for (const x of [-136.5, -73.5]) {
    out.push(S(k.cylinder(x, -41, 2.2, 6.5, 38, P, 20), { tone: "mid" }));
    out.push(S(k.cylinder(x, -41, 3.1, 43, 1.4, P, 20), { tone: "lo" }));
  }

  const beam = { x: -141, y: -45, w: 72, d: 6, r: 1.5 };
  out.push(S(k.slabOf(beam, 44.4, 4.2, P, 4, 0.6), { tone: "mid" }));
  out.push(L(k.planOutline(k.insetPlan(beam, 2), 48.6, P, 4), { tone: "lo" }));
  const carriage = { x: -118, y: -21, w: 27, d: 24, r: 3 };
  out.push(S(k.slabOf(carriage, 35, 5.5, P, 5, 0.6), { tone: "hi" }));
  out.push(L(k.planOutline(k.insetPlan(carriage, 2), 40.5, P, 4), { tone: "faint" }));
  const barrel = [-104.5, -9];
  out.push(S(k.cylinder(barrel[0], barrel[1], 6.5, 30.5, 3, P, 32, 0.4), { tone: "mid" }));
  out.push(L(k.knurl(barrel[0], barrel[1], 6.5, 31, 33, 24, P, 0.5), { tone: "lo" }));
  out.push(S(k.cylinder(barrel[0], barrel[1], 4, 29.4, 1.1, P, 28), { tone: "hi" }));
  out.push(L(k.ring(barrel[0], barrel[1], 2.4, 30.5, P, 24), { tone: "lo" }));
  out.push(D([at([barrel[0], barrel[1], 30.6])], { size: 0.75, tone: "mid" }));
  const scanLine = k.lineOnTop([EVIDENCE.x + 5, -9], [EVIDENCE.x + EVIDENCE.w - 5, -9], 5.15, P);
  out.push(L(scanLine, { tone: "hi", dashed: true }));
  for (const x of [-136.5, -73.5]) out.push(D([at([x, -41, 48.7]), at([x, -41, 46.7])], { size: 0.42, tone: "lo" }));
  return out.join("");
}

function dial({ center, radius, z, name, tickCount, tickEvery, start, span, indexCount, initialIndex, selector = false }) {
  const [cx, cy] = center;
  const out = [];
  const pedestal = { x: cx - radius - 4, y: cy - radius - 4, w: (radius + 4) * 2, d: (radius + 4) * 2, r: 6 };
  out.push(S(k.slabOf(pedestal, 0, 4, P, 6, 0.6), { tone: "mid" }));
  out.push(S(k.cylinder(cx, cy, radius + 1.6, 4, 2.4, P, 56, 0.55), { tone: "lo" }));
  out.push(L(k.knurl(cx, cy, radius + 1.2, 4.7, 6.2, 56, P, 0.45), { tone: "faint" }));
  out.push(S(k.cylinder(cx, cy, radius, 6.4, 2, P, 56, 0.3), { tone: "hi" }));
  out.push(S(k.cylinder(cx, cy, radius - 3, 8.4, 2, P, 56, 0.25), { tone: "mid" }));
  out.push(L(k.ring(cx, cy, radius - 5, 10.4, P, 56), { tone: "lo" }));
  const marks = k.radialTicks(cx, cy, radius - 7, tickCount, tickEvery, 10.4, [1.8, 3.3], P, start, span);
  out.push(L(marks.minor, { tone: "faint" }), L(marks.major, { tone: "hi" }));
  const indicator = { x: cx - 5, y: cy + radius - 1, w: 10, d: 4, r: 1.5 };
  out.push(S(k.slabOf(indicator, 8.5, 2, P, 3, 0.25), { tone: "lo" }));
  out.push(S(k.cylinder(cx, cy, 2.7, 10.4, 1.5, P, 28), { tone: "lo" }));
  out.push(S(k.cylinder(cx, cy, 1.3, 11.9, 1.1, P, 24), { tone: "hi" }));
  const valueAt = (index) => {
    const angle = start + (index / indexCount) * span;
    const r = radius - 9;
    return k.lineOnTop([cx, cy], [cx + Math.sin(angle) * r, cy - Math.cos(angle) * r], 13.05, P);
  };
  const initial = valueAt(initialIndex);
  const needlePath = L(initial, { tone: "hi", free: true }).replace("<path ", `<path id="${name}-needle" `);
  out.push(needlePath);
  out.push(D([at([cx + Math.sin(start + (initialIndex / indexCount) * span) * (radius - 9), cy - Math.cos(start + (initialIndex / indexCount) * span) * (radius - 9), 13.05])], { size: 0.65, tone: "hi" }));

  if (selector) {
    const slot = { x: cx + radius - 9, y: cy + radius - 8, w: 11, d: 9, r: 1.5 };
    out.push(S(k.slabOf(slot, 10.5, 1.3, P, 3, 0.2), { tone: "lo" }));
    const unknown = S(k.cylinder(cx + radius - 3.5, cy + radius - 3.5, 1.7, 11.8, 0.9, P, 20), { tone: "hi", lit: true }).replace("<g class=\"iso-solid\"", '<g id="severity-unknown-indicator" class="iso-solid"');
    out.push(`<g id="severity-unknown-state" style="opacity:0">${unknown}</g>`);
    out.push(L(k.ring(cx + radius - 3.5, cy + radius - 3.5, 1.7, 12.7, P, 16), { tone: "lo" }));
  }
  out.push(S(k.cylinder(cx, cy, 0.7, 13.1, 0.5, P, 16), { tone: "hi" }));
  return { markup: out.join(""), needlePath: initial, valueAt };
}

function reportSlip() {
  const out = [];
  out.push(S(k.slabOf(REPORT, 0, 2.2, P, 5, 0.3), { tone: "lo" }));
  const card = { x: REPORT.x + 2, y: REPORT.y + 3, w: REPORT.w - 4, d: REPORT.d - 6, r: 1.5 };
  out.push(S(k.slabOf(card, 2.2, 1.4, P, 4, 0.2), { tone: "hi", lit: true }));
  const rows = ["medium", "high", "unknown", "not-validated"];
  const rowYs = [REPORT.y + 17, REPORT.y + 35, REPORT.y + 53, REPORT.y + 71];
  for (let index = 0; index < rowYs.length; index++) {
    if (index) out.push(L(k.lineOnTop([card.x + 3, rowYs[index] - 6], [card.x + card.w - 3, rowYs[index] - 6], REPORT_TOP + 0.05, P), { tone: "faint" }));
    let text = k.faceTextSvg(k.topMatrix([card.x + 4, rowYs[index]], REPORT_TOP + 0.05, P), rows[index], { size: index === 3 ? 2.3 : 2.8, tone: "mid" });
    if (index === 0) text = text.replace("<text ", '<text id="severity-value" ');
    if (index === 1) text = text.replace("<text ", '<text id="confidence-value" ');
    out.push(text);
  }
  const clamps = [
    { x: REPORT.x + 1, y: REPORT.y + 2, w: REPORT.w - 2, d: 3, r: 0.8 },
    { x: REPORT.x + 1, y: REPORT.y + REPORT.d - 5, w: REPORT.w - 2, d: 3, r: 0.8 },
  ];
  for (const clamp of clamps) out.push(S(k.slabOf(clamp, 3.5, 1.2, P, 3, 0.2), { tone: "mid" }));
  for (const y of [REPORT.y + 3, REPORT.y + REPORT.d - 4]) {
    out.push(D([at([REPORT.x + 4, y, 4.7]), at([REPORT.x + REPORT.w - 4, y, 4.7])], { size: 0.42, tone: "lo" }));
  }
  return out.join("");
}

const severityDial = dial({
  center: [SEVERITY.x, SEVERITY.y],
  radius: SEVERITY.radius,
  z: SEVERITY.z,
  name: "severity",
  tickCount: 4,
  tickEvery: 1,
  start: SEVERITY_START,
  span: SEVERITY_SPAN,
  indexCount: 4,
  initialIndex: severitySample,
  selector: true,
});
const confidenceDial = dial({
  center: [CONFIDENCE.x, CONFIDENCE.y],
  radius: CONFIDENCE.radius,
  z: CONFIDENCE.z,
  name: "confidence",
  tickCount: 2,
  tickEvery: 1,
  start: CONFIDENCE_START,
  span: CONFIDENCE_SPAN,
  indexCount: 2,
  initialIndex: confidenceSample,
});

const LABEL = "A conceptual FUSE finding review station. A redacted evidence card sits under a reader, separate severity and confidence instruments feed a report slip, and applicability and validation remain distinct fields. This is a teaching model, not FUSE hardware.";
const bodyParts = [
  base(),
  evidenceTray(),
  severityDial.markup,
  confidenceDial.markup,
  reportSlip(),
];

const staticDarkSvg = k.figureSvg({ width: WIDTH, height: HEIGHT, label: LABEL, body: bodyParts, standalone: "dark" });
const staticLightSvg = k.figureSvg({ width: WIDTH, height: HEIGHT, label: LABEL, body: bodyParts, standalone: "light" });
const pathSeries = (valueAt, indexCount, stepsPerIndex) =>
  Array.from({ length: indexCount * stepsPerIndex + 1 }, (_, step) => valueAt(step / stepsPerIndex));
const severityPaths = pathSeries(severityDial.valueAt, 4, 24);
const confidencePaths = pathSeries(confidenceDial.valueAt, 2, 24);

const controls = `
<section class="finding-controls" aria-label="Illustrative finding fields">
  <label class="finding-control" for="severity-input">
    <span class="finding-control-heading">Potential impact severity</span>
    <span class="finding-control-help">Choose a category. Unknown is outside the ordered scale.</span>
    <select id="severity-input" aria-describedby="independence-note">
      <option value="critical">Critical</option><option value="high">High</option>
      <option value="medium" selected>Medium</option><option value="low">Low</option>
      <option value="info">Info</option><option value="unknown">Unknown</option>
    </select>
  </label>
  <label class="finding-control" for="confidence-input">
    <span class="finding-control-heading">Evidence confidence</span>
    <span class="finding-control-help">Move this control without changing severity.</span>
    <span class="confidence-input-row"><input id="confidence-input" type="range" min="0" max="2" step="1" value="2"><output id="confidence-output" for="confidence-input">High</output></span>
    <span class="confidence-ticks" aria-hidden="true"><span>Low</span><span>Medium</span><span>High</span></span>
  </label>
  <p class="independence-note" id="independence-note">Each control updates its own field. FUSE does not combine severity and confidence into a risk score.</p>
  <p class="fixed-context">Example context: applicability <strong>unknown</strong> · validation <strong>not validated</strong></p>
</section>`;

const initialReadout = `severity: medium · confidence: high`;
const figure = k.plateHtml({
  fig: "FINDING MODEL",
  title: "Evidence stays separate from impact",
  hint: "Adjust either field below",
  readout: initialReadout,
  keys: [
    { mark: "lit", label: "Report slip: severity, confidence, applicability, validation" },
    { mark: "raised", label: "Separate controls preserve independent judgments" },
  ],
  caption: "Conceptual teaching model, not a scan result or a physical FUSE device. Starting values match the illustrative FUSE001 schema example. The severity categories are discrete; unknown is not a lower severity. Static evidence is not lab validation.",
  body: `<div class="finding-stage">${k.figureSvg({ width: WIDTH, height: HEIGHT, label: LABEL, body: bodyParts })}</div>${controls}`,
});

const live = `
const severityPaths = ${JSON.stringify(severityPaths)};
const confidencePaths = ${JSON.stringify(confidencePaths)};
const severityValues = ${JSON.stringify(SEVERITY_ORDER)};
const confidenceValues = ${JSON.stringify(CONFIDENCE_ORDER)};
const severityNeedle = document.getElementById("severity-needle");
const confidenceNeedle = document.getElementById("confidence-needle");
const severityUnknown = document.getElementById("severity-unknown-state");
const severityInput = document.getElementById("severity-input");
const confidenceInput = document.getElementById("confidence-input");
const confidenceOutput = document.getElementById("confidence-output");
const severityOutput = document.getElementById("severity-value");
const confidenceValue = document.getElementById("confidence-value");
const readout = document.querySelector("[data-readout]");
const stage = document.querySelector(".finding-stage");
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
const state = { severity: 2, severityTarget: 2, confidence: 2, confidenceTarget: 2 };
let visible = false, frame = 0, last = 0;
const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
function draw() {
  const severityIndex = Math.round(state.severity * 24);
  const confidenceIndex = Math.round(state.confidence * 24);
  severityNeedle.setAttribute("d", severityPaths[severityIndex]);
  confidenceNeedle.setAttribute("d", confidencePaths[confidenceIndex]);
  const selectedSeverity = severityInput.value;
  const selectedConfidence = confidenceValues[Number(confidenceInput.value)];
  const severityUnknownSelected = selectedSeverity === "unknown";
  severityNeedle.style.opacity = severityUnknownSelected ? "0" : "1";
  severityUnknown.style.opacity = severityUnknownSelected ? "1" : "0";
  severityOutput.textContent = selectedSeverity;
  confidenceValue.textContent = selectedConfidence;
  confidenceOutput.value = selectedConfidence[0].toUpperCase() + selectedConfidence.slice(1);
  confidenceInput.setAttribute("aria-valuetext", selectedConfidence);
  readout.textContent = "severity: " + selectedSeverity + " · confidence: " + selectedConfidence;
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  const calm = reducedMotion.matches;
  for (const key of ["severity", "confidence"]) {
    const target = state[key + "Target"];
    state[key] = calm ? target : state[key] + (target - state[key]) * (1 - Math.exp(-dt / 0.22));
    if (Math.abs(target - state[key]) < 0.002) state[key] = target;
  }
  draw();
  const settled = state.severity === state.severityTarget && state.confidence === state.confidenceTarget;
  frame = visible && !settled ? requestAnimationFrame(tick) : 0;
}
function run() {
  if (reducedMotion.matches) { state.severity = state.severityTarget; state.confidence = state.confidenceTarget; draw(); return; }
  if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); }
}
severityInput.addEventListener("change", () => {
  const next = severityValues.indexOf(severityInput.value);
  if (next >= 0) state.severityTarget = next;
  run();
});
confidenceInput.addEventListener("input", () => {
  state.confidenceTarget = clamp(Number(confidenceInput.value), 0, confidenceValues.length - 1);
  run();
});
new IntersectionObserver((entries) => {
  visible = entries[entries.length - 1].isIntersecting;
  if (visible) run();
  else if (frame) { cancelAnimationFrame(frame); frame = 0; }
}, { rootMargin: "120px 0px" }).observe(stage);
const themeButton = document.querySelector("[data-theme-toggle]");
themeButton.addEventListener("click", () => {
  const light = document.body.dataset.theme !== "light";
  document.body.dataset.theme = light ? "light" : "dark";
  themeButton.textContent = light ? "Use dark theme" : "Use light theme";
  themeButton.setAttribute("aria-pressed", String(light));
});
draw();
`;

const styles = `
.finding-tools{display:flex;justify-content:flex-end;margin:0 0 12px}
.finding-theme{border:1px solid var(--anatomy-faint);border-radius:999px;background:var(--anatomy-card);color:var(--anatomy-text);padding:7px 12px;font:inherit;cursor:pointer}
.finding-theme:focus-visible,.finding-controls :focus-visible{outline:2px solid var(--anatomy-strong);outline-offset:3px}
.finding-stage{width:100%;touch-action:pan-y}
.finding-controls{display:grid;grid-template-columns:1fr 1fr;gap:14px 22px;margin:2px 16px 10px;padding-top:14px;border-top:1px solid var(--anatomy-faint)}
.finding-control{display:grid;gap:6px;align-content:start}
.finding-control-heading{color:var(--anatomy-strong);font-weight:600}
.finding-control-help,.confidence-ticks{color:var(--anatomy-muted);font-size:12px}
.finding-control select{width:100%;border:1px solid var(--anatomy-faint);border-radius:6px;background:var(--anatomy-card);color:var(--anatomy-strong);padding:8px;font:inherit}
.confidence-input-row{display:flex;align-items:center;gap:12px}
.confidence-input-row input{width:100%;accent-color:var(--anatomy-strong)}
.confidence-input-row output{min-width:52px;color:var(--anatomy-strong);font-family:var(--anatomy-mono);text-align:right;text-transform:uppercase}
.confidence-ticks{display:flex;justify-content:space-between;padding-right:64px}
.independence-note,.fixed-context{grid-column:1/-1;margin:0;color:var(--anatomy-muted);font-size:12px}
.fixed-context{margin-top:-10px}
.fixed-context strong{color:var(--anatomy-text);font-weight:500}
#severity-needle,#confidence-needle{transition:opacity .16s ease}
@media(max-width:600px){.finding-controls{grid-template-columns:1fr;margin-inline:10px}.independence-note,.fixed-context{grid-column:1}.fixed-context{margin-top:-8px}}
@media(prefers-reduced-motion:reduce){#severity-needle,#confidence-needle{transition:none}}
`;
const themeToolbar = `<div class="finding-tools"><button class="finding-theme" type="button" data-theme-toggle aria-pressed="false">Use light theme</button></div>`;
const page = k.pageHtml({ title: "FUSE finding model", theme: "dark", body: `${themeToolbar}${figure}`, script: live, width: 940 })
  .replace("</head>", `<style>${styles}</style></head>`);

mkdirSync(DOC_FIGURES, { recursive: true });
mkdirSync(SITE_DIAGRAMS, { recursive: true });
writeFileSync(resolve(DOC_FIGURES, "fuse-finding-model.svg"), staticDarkSvg, "utf8");
writeFileSync(resolve(DOC_FIGURES, "fuse-finding-model-light.svg"), staticLightSvg, "utf8");
writeFileSync(resolve(SITE_DIAGRAMS, "fuse-finding-model.html"), page, "utf8");
console.log(`Built conceptual finding model with ${partCount} named parts.`);
console.log("Wrote docs/figures/fuse-finding-model.svg and docs/figures/fuse-finding-model-light.svg.");
console.log("Wrote site/diagrams/fuse-finding-model.html.");
