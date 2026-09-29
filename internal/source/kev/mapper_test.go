package kev

import "testing"

func TestMapResponseSkipsEmptyCVEID(t *testing.T) {
	resp := apiResponse{
		Vulnerabilities: []apiVuln{
			{CVEID: "CVE-2021-41773", VendorProject: "Apache"},
			{CVEID: "", VendorProject: "Skipped"},
		},
	}
	out := mapResponse(resp)
	if len(out) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(out))
	}
	if _, ok := out["CVE-2021-41773"]; !ok {
		t.Fatal("CVE-2021-41773 missing")
	}
}

func TestMapVulnerability(t *testing.T) {
	v := apiVuln{
		CVEID:                      "CVE-2017-0144",
		VendorProject:              "Microsoft",
		Product:                    "Windows",
		DateAdded:                  "2021-11-03",
		ShortDescription:           "EternalBlue",
		RequiredAction:             "Apply updates.",
		DueDate:                    "2021-11-17",
		KnownRansomwareCampaignUse: "Known",
	}
	got := mapVulnerability(v)
	if got.CVEID != "CVE-2017-0144" {
		t.Fatalf("CVEID = %q", got.CVEID)
	}
	if got.KnownRansomware != "Known" {
		t.Fatalf("KnownRansomware = %q", got.KnownRansomware)
	}
}
