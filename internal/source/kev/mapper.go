package kev

import "github.com/Lutfifakee-Project/cevrixa/internal/domain"

func mapVulnerability(v apiVuln) domain.KEVInfo {
	return domain.KEVInfo{
		CVEID:            v.CVEID,
		VendorProject:    v.VendorProject,
		Product:          v.Product,
		DateAdded:        v.DateAdded,
		ShortDescription: v.ShortDescription,
		RequiredAction:   v.RequiredAction,
		DueDate:          v.DueDate,
		KnownRansomware:  v.KnownRansomwareCampaignUse,
	}
}

func mapResponse(r apiResponse) map[string]domain.KEVInfo {
	out := make(map[string]domain.KEVInfo, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		out[v.CVEID] = mapVulnerability(v)
	}
	return out
}
