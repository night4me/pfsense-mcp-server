"""Task Phase 13: prove official guidance and observed live pfSense state
remain structurally separate, using the three scenarios named explicitly
in this release's authorizing instructions.

This is not a new isolation mechanism -- it exercises the *already*
G1/G4-enforced structural separation (`GuidanceReference`/
`EvidenceReference` have no field that could carry or be derived from
live appliance state; the guidance package has no import path to any
transport or READ tool) against three concrete, named scenarios, so the
guarantee is demonstrated for the specific failure modes an AI client
could plausibly conflate, not only proven abstractly by AST scan.
"""

from __future__ import annotations

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.guidance.appliance_identity import ObservedEdition
from pfsense_mcp.guidance.bridge import bridge_guidance_reference
from pfsense_mcp.guidance.models import (
    DocumentSource,
    Edition,
    EvidenceLevel,
    GuidanceReference,
    RetrievalMode,
    excerpt_hash,
)
from pfsense_mcp.guidance.registry import lookup_guidance


def test_scenario_a_dns_resolver_guidance_never_encodes_the_observed_enabled_flag():
    """Scenario A: a live READ tool might report `dnsresolver.enable =
    false`. Guidance for the same capability must explain what the DNS
    Resolver *is*, and must never assert (or be able to assert) that
    *this appliance* has it disabled -- because nothing in its schema can
    carry that live fact in the first place.
    """
    guidance_off = lookup_guidance(
        Capability.SERVICES_DNS_RESOLVER_READ, observed_version=None, observed_edition=ObservedEdition.UNKNOWN
    )
    guidance_on = lookup_guidance(
        Capability.SERVICES_DNS_RESOLVER_READ, observed_version="2.9.0", observed_edition=ObservedEdition.KNOWN_CE
    )
    assert len(guidance_off) == 1
    assert len(guidance_on) == 1
    # Identical summary regardless of what a caller claims the observed
    # appliance state is -- proof the summary is fixed registry data, not
    # derived from (or reactive to) any live fact.
    assert guidance_off[0].summary == guidance_on[0].summary
    assert "enable" not in GuidanceReference.model_fields
    assert "enabled" not in GuidanceReference.model_fields
    assert "status" not in GuidanceReference.model_fields


def test_scenario_b_gateway_guidance_never_encodes_the_observed_down_state():
    """Scenario B: a live READ tool might report a gateway as down.
    Guidance may explain what gateway monitoring does, but must never be
    treated as evidence the gateway actually is down -- because
    `GuidanceReference`/`EvidenceReference` carry no operational-status
    field at all, live or otherwise.
    """
    result = lookup_guidance(Capability.GATEWAY_READ, observed_version=None, observed_edition=ObservedEdition.UNKNOWN)
    assert len(result) == 1
    reference = result[0]
    status_like_fields = {"status", "is_down", "is_up", "state", "reachable", "latency", "packet_loss"}
    assert status_like_fields.isdisjoint(GuidanceReference.model_fields)
    # The summary is definitional prose about what a gateway *is*, never a
    # live status sentence -- spot-check it does not itself assert an
    # up/down fact about any specific appliance.
    assert "is down" not in reference.summary.lower()
    assert "is up" not in reference.summary.lower()


def test_scenario_c_firewall_rule_editing_guidance_creates_no_write_authorization():
    """Scenario C: documentation describing how to edit a firewall rule
    must never create WRITE authorization or make a WRITE tool reachable
    -- even when the excerpt text itself uses imperative, instructional
    language ("click Save", "click Apply Changes").
    """
    instructional_excerpt = (
        "To edit a firewall rule, navigate to Firewall > Rules, click the "
        "pencil icon next to the rule, make changes, then click Save and "
        "Apply Changes to activate the new ruleset."
    )
    synthetic = DocumentSource(
        source_id="synthetic_edit_rule_doc",
        title="Editing a firewall rule (synthetic, test-only)",
        canonical_url="https://docs.netgate.com/synthetic-edit-rule",
        pfsense_edition=Edition.BOTH,
        version_applicability="unversioned",
        evidence_level=EvidenceLevel.INFERRED_FROM_CURRENT_DOCS,
        retrieval_mode=RetrievalMode.BUNDLED_SNAPSHOT,
        summary=instructional_excerpt,
        summary_hash=excerpt_hash(instructional_excerpt),
        source_verification_excerpt="Synthetic verification anchor (test-only).",
        source_verification_hash=excerpt_hash("Synthetic verification anchor (test-only)."),
        license_note="Synthetic, test-only.",
    )
    reference = GuidanceReference(
        capability=Capability.FIREWALL_READ.name,
        source_id=synthetic.source_id,
        title=synthetic.title,
        canonical_url=synthetic.canonical_url,
        summary=synthetic.summary,
        summary_hash=synthetic.summary_hash,
        pfsense_edition=synthetic.pfsense_edition,
        trust_label="pinned-summary",
        applicability="applicable",  # type: ignore[arg-type]
        evidence_level=synthetic.evidence_level,
        applicable_overlay_chain=(),
        observed_edition_used=ObservedEdition.UNKNOWN,
        observed_version_used=None,
        retrieval_mode=synthetic.retrieval_mode,
        snapshot_version="test-only",
    )
    # G1, re-checked against this specific, adversarial-flavored (but
    # realistic) instructional content: no field of any type that could
    # be read as a capability, endpoint, HTTP method, or confirmation
    # token exists on the object this instructional text produced.
    forbidden_field_names = {
        "endpoint",
        "method",
        "http_method",
        "capability_grant",
        "confirmation_token",
        "confirmation",
        "signature",
        "authorization",
        "write_enabled",
    }
    assert forbidden_field_names.isdisjoint(type(reference).model_fields)
    bridged = bridge_guidance_reference(reference)
    assert forbidden_field_names.isdisjoint(type(bridged).model_fields)
    # The instructional text itself is preserved verbatim as inert data,
    # never parsed into an action.
    assert bridged.summary == instructional_excerpt
