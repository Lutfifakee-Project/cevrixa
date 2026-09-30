package nvd

import (
	"encoding/json"
	"testing"
)

// realShape mirrors the structure the NVD API 2.0 actually returns (verified
// against services.nvd.nist.gov for CVE-2016-5425): configurations[0] carries
// an operator and a "nodes" array, and cpeMatch lives inside those nodes.
const realShape = `{
  "operator": "AND",
  "nodes": [
    {
      "operator": "OR",
      "negate": false,
      "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"},
        {"vulnerable": false, "criteria": "cpe:2.3:o:redhat:enterprise_linux:7:*:*:*:*:*:*:*"}
      ]
    },
    {
      "operator": "OR",
      "negate": false,
      "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:oracle:instantis_enterprisetrack:17.1:*:*:*:*:*:*:*"}
      ]
    }
  ]
}`

const legacyShape = `{
  "operator": "OR",
  "negate": false,
  "children": [
    {
      "operator": "OR",
      "cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"}
      ]
    }
  ],
  "cpeMatch": [
    {"vulnerable": true, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
  ]
}`

func TestMapNodeReadsAPINodesField(t *testing.T) {
	var node apiConfigNode
	if err := json.Unmarshal([]byte(realShape), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := mapNode(node)

	if got.Operator != "AND" {
		t.Fatalf("Operator = %q, want AND", got.Operator)
	}
	if len(got.Children) != 2 {
		t.Fatalf("nested nodes were dropped: %+v", got)
	}
	if len(got.Children[0].Matches) != 2 {
		t.Fatalf("cpeMatch inside nodes was dropped: %+v", got.Children[0])
	}
	if got.Children[0].Matches[1].Vulnerable {
		t.Fatal("vulnerable:false must be preserved, it is an AND requirement")
	}
	if got.Children[0].Matches[0].Criteria != "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*" {
		t.Fatalf("criteria = %q", got.Children[0].Matches[0].Criteria)
	}
	if len(got.Children[1].Matches) != 1 {
		t.Fatalf("second node matches = %d, want 1", len(got.Children[1].Matches))
	}
}

func TestMapNodeReadsLegacyChildrenField(t *testing.T) {
	var node apiConfigNode
	if err := json.Unmarshal([]byte(legacyShape), &node); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := mapNode(node)

	if len(got.Children) != 1 || len(got.Children[0].Matches) != 1 {
		t.Fatalf("legacy children were dropped: %+v", got)
	}
	if len(got.Matches) != 1 {
		t.Fatalf("direct cpeMatch was dropped: %+v", got)
	}
}

func TestDedupeReferencesCollapsesRepeatedURLs(t *testing.T) {
	// NVD lists the same advisory once per contributing source. Real records
	// showed the same five URLs repeated, which inflated the evidence list.
	refs := []apiReference{
		{URL: "https://example.test/a", Tags: []string{"Vendor Advisory"}},
		{URL: "https://example.test/a", Tags: []string{"Patch"}},
		{URL: "https://example.test/a", Tags: []string{"vendor advisory"}},
		{URL: "https://example.test/b"},
		{URL: ""},
	}

	got := dedupeReferences(refs)

	if len(got) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(got), got)
	}
	if len(got[0].Tags) != 2 {
		t.Fatalf("tags = %v, want the two distinct tags merged", got[0].Tags)
	}
	if got[1].URL != "https://example.test/b" {
		t.Fatalf("order changed: %+v", got)
	}
}

func TestMapNodeReadsRealRecordIntoVulnerability(t *testing.T) {
	// End to end through the CVE mapper, using the real configuration shape.
	vuln := mapVulnerability(apiCVE{
		ID:               "CVE-2016-5425",
		SourceIdentifier: "secalert@redhat.com",
		VulnStatus:       "Modified",
		Descriptions:     []apiDescription{{Lang: "en", Value: "tomcat"}},
		Configurations: []apiConfigNode{
			func() apiConfigNode {
				var n apiConfigNode
				if err := json.Unmarshal([]byte(realShape), &n); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				return n
			}(),
		},
	})

	if len(vuln.Applicability) != 1 {
		t.Fatalf("applicability = %+v", vuln.Applicability)
	}
	total := 0
	for _, child := range vuln.Applicability[0].Children {
		total += len(child.Matches)
	}
	if total != 3 {
		t.Fatalf("mapped %d criteria, want 3: %+v", total, vuln.Applicability)
	}
}
