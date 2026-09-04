# Use a typed SSH posture schema

The next incompatible report schema replaces SSH posture encoded in `services[].protocol_details` with a typed model containing complete, partial, and indeterminate outcomes. Historical map-based SSH posture is deliberately not migrated or interpreted by a compatibility adapter: avoiding two authoritative representations is more valuable than preserving that portion of old reports. Partial algorithm selections remain serialized as evidence, but only a complete posture can support a legacy-algorithm finding.
