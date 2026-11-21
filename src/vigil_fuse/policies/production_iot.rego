package fuse.policy

import rego.v1

policy_id := "fuse.reference.production-iot"

violation_set contains {"rule": "no_plaintext_mqtt", "evidence_refs": signal.evidence_refs, "message": "Plaintext MQTT was observed in the scanned evidence."} if {
	signal := input.evidence.plaintext_mqtt
	signal.status == "observed"
}

unknown_set contains {"rule": "no_plaintext_mqtt", "evidence_refs": signal.evidence_refs, "message": "FUSE did not have complete evidence to determine whether plaintext MQTT is present."} if {
	signal := input.evidence.plaintext_mqtt
	signal.status == "unknown"
}

violation_set contains {"rule": "tls_verification_required", "evidence_refs": signal.evidence_refs, "message": "A TLS verification bypass was observed in the scanned evidence."} if {
	signal := input.evidence.tls_verification
	signal.status == "bypass_observed"
}

unknown_set contains {"rule": "tls_verification_required", "evidence_refs": signal.evidence_refs, "message": "The evidence does not confirm that TLS peer verification is required."} if {
	signal := input.evidence.tls_verification
	signal.status != "bypass_observed"
	signal.status != "verification_confirmed"
}

violation_set contains {"rule": "signed_firmware_required", "evidence_refs": [], "message": "Evidence explicitly identifies unsigned firmware."} if {
	input.firmware.signature_status == "unsigned"
}

unknown_set contains {"rule": "signed_firmware_required", "evidence_refs": [], "message": "FUSE has not verified firmware signature state."} if {
	input.firmware.signature_status != "unsigned"
	input.firmware.signature_status != "verified"
}

violation_set contains {"rule": "no_externally_exposed_debug", "evidence_refs": input.evidence.debug_interface_exposure.evidence_refs, "message": "Evidence explicitly identifies an externally exposed debug interface."} if {
	input.evidence.debug_interface_exposure.status == "externally_exposed"
}

unknown_set contains {"rule": "no_externally_exposed_debug", "evidence_refs": input.evidence.debug_interface_exposure.evidence_refs, "message": "File-based debug-net candidates do not establish physical or runtime exposure."} if {
	input.evidence.debug_interface_exposure.status != "externally_exposed"
	input.evidence.debug_interface_exposure.status != "not_exposed"
}

violation_set contains {"rule": "no_private_key_material", "evidence_refs": signal.evidence_refs, "message": "A private-key PEM marker was observed in the scanned evidence."} if {
	signal := input.evidence.private_key_material
	signal.status == "observed"
}

unknown_set contains {"rule": "no_private_key_material", "evidence_refs": signal.evidence_refs, "message": "FUSE did not have complete evidence to determine whether private-key material is present."} if {
	signal := input.evidence.private_key_material
	signal.status == "unknown"
}

violation_set contains {"rule": "no_unresolved_high_findings", "evidence_refs": signal.evidence_refs, "message": "An applicable, unresolved high or critical FUSE finding violates this organizational policy."} if {
	signal := input.evidence.unresolved_high_findings
	signal.status == "unresolved"
}

unknown_set contains {"rule": "no_unresolved_high_findings", "evidence_refs": signal.evidence_refs, "message": "FUSE could not determine whether all high or critical findings are resolved."} if {
	signal := input.evidence.unresolved_high_findings
	signal.status in {"uncertain", "unknown"}
}

violation_list := [item | some item in violation_set]
unknown_list := [item | some item in unknown_set]

status := "fail" if count(violation_list) > 0
status := "unknown" if {
	count(violation_list) == 0
	count(unknown_list) > 0
}
status := "pass" if {
	count(violation_list) == 0
	count(unknown_list) == 0
}

result := {
	"policy_id": policy_id,
	"status": status,
	"violations": violation_list,
	"unknowns": unknown_list,
	"mappings": [],
}
