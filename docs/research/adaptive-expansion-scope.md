# Adaptive analysis expansion

This is a proposed post-0.4.0 scope. The 0.4.0 completion record remains a
historical record of the earlier release and does not cover this expansion.

The existing scan pipeline uses bounded discovery, advisory framework hints,
normalized findings and optional analyzers. RepoDNA and the analysis router
must preserve those limits and avoid changing existing passive scan behavior.
Active network analysis requires a separate explicit authorization and scope
boundary. Detected endpoints are evidence only and are never targets by default.

Implementation order: RepoDNA, component graph, target model, router, evidence
model, optional adapters, validation and correlation, policy, reporting, then
optional Kubernetes orchestration. No integration described here is implemented
or supported solely by this document.
