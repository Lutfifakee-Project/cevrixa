package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

const sarifSchema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
const sarifVersion = "2.1.0"

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifMessage   `json:"shortDescription,omitempty"`
	FullDescription  sarifMessage   `json:"fullDescription,omitempty"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifMessage    `json:"message"`
	Locations  []sarifLocation `json:"locations,omitempty"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

func RenderSARIF(w io.Writer, r domain.Report, toolVersion string) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    []sarifRun{buildRun(r, toolVersion)},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func levelFromStatus(f domain.Finding) string {
	switch f.Status {
	case domain.FindingStatusAffected:
		if f.KnownExploited != nil {
			return "error"
		}
		return "warning"
	case domain.FindingStatusNotAffected:
		return "note"
	default:
		return "none"
	}
}

func buildSARIFMessage(t domain.Target, f domain.Finding) string {
	target := t.Product
	if target == "" {
		target = t.PURL
	}
	if target == "" {
		target = t.CPE
	}
	return fmt.Sprintf(
		"%s is %s (confidence: %s). Fixed in: %v",
		target, f.Status, f.Confidence, f.FixedVersions,
	)
}

func artifactURI(t domain.Target) string {
	if t.PURL != "" {
		return t.PURL
	}
	if t.CPE != "" {
		return t.CPE
	}
	if t.Product != "" && t.Version != "" {
		return t.Product + "@" + t.Version
	}
	return "unknown"
}

func buildResultProperties(f domain.Finding) map[string]any {
	props := map[string]any{
		"status":     string(f.Status),
		"confidence": string(f.Confidence),
	}
	if len(f.FixedVersions) > 0 {
		props["fixed_versions"] = f.FixedVersions
	}
	if f.Applicability.Range != "" {
		props["applicability_range"] = f.Applicability.Range
	}
	if f.Applicability.Source != "" {
		props["evidence_source"] = f.Applicability.Source
	}
	if f.KnownExploited != nil {
		props["known_exploited"] = true
		if f.KnownExploited.DateAdded != "" {
			props["kev_date_added"] = f.KnownExploited.DateAdded
		}
	}
	return props
}

// RenderSARIFMulti produces a single SARIF log with one run per report.
func RenderSARIFMulti(w io.Writer, reports []domain.Report, toolVersion string) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs:    []sarifRun{},
	}
	for _, r := range reports {
		run := buildRun(r, toolVersion)
		log.Runs = append(log.Runs, run)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func buildRun(r domain.Report, toolVersion string) sarifRun {
	driver := sarifDriver{
		Name:           "Cevrixa",
		Version:        toolVersion,
		InformationURI: "https://github.com/Lutfifakee-Project/cevrixa",
	}

	seenRules := map[string]bool{}
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0)

	for _, f := range r.Findings {
		if !seenRules[f.VulnerabilityID] {
			seenRules[f.VulnerabilityID] = true
			rules = append(rules, sarifRule{
				ID:               f.VulnerabilityID,
				Name:             f.VulnerabilityID,
				ShortDescription: sarifMessage{Text: "Vulnerability affecting target"},
				Properties: map[string]any{
					"status":     string(f.Status),
					"confidence": string(f.Confidence),
				},
			})
		}
		results = append(results, sarifResult{
			RuleID: f.VulnerabilityID,
			Level:  levelFromStatus(f),
			Message: sarifMessage{
				Text: buildSARIFMessage(r.Target, f),
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: artifactURI(r.Target),
						},
					},
				},
			},
			Properties: buildResultProperties(f),
		})
	}

	driver.Rules = rules
	return sarifRun{
		Tool:    sarifTool{Driver: driver},
		Results: results,
	}
}
