package domain

// Remediation is the derived fix guidance for a finding. It is computed from
// data the engine already holds (a fixed version, an enrichment mitigation);
// it never invents a recommendation. When no fixed version is known, the
// remediation says so rather than guessing.
type Remediation struct {
	// Action is a short imperative, for example "upgrade" or "monitor".
	Action string `json:"action,omitempty"`
	// FixedVersion is the version the target should move to, when known.
	FixedVersion string `json:"fixed_version,omitempty"`
	// Note explains the action, or why no action is available.
	Note string `json:"note,omitempty"`
}

// BuildRemediation derives fix guidance for a finding. Only an affected finding
// needs remediation; a not_affected or inconclusive finding has nothing to fix
// and yields an empty Remediation.
func BuildRemediation(f Finding) Remediation {
	if f.Status != FindingStatusAffected {
		return Remediation{}
	}

	fixed := ""
	if len(f.FixedVersions) > 0 {
		fixed = f.FixedVersions[0]
	}

	if fixed != "" {
		return Remediation{
			Action:       "upgrade",
			FixedVersion: fixed,
			Note:         "upgrade to " + fixed + " or later",
		}
	}

	// No fixed version is known. State that honestly; do not fabricate one.
	note := "no fixed version is known; monitor for an update"
	if f.Enrichment != nil && f.Enrichment.Mitigation != "" {
		note = f.Enrichment.Mitigation
	}
	return Remediation{
		Action: "monitor",
		Note:   note,
	}
}
