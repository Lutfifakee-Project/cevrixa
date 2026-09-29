package domain

type KEVInfo struct {
	CVEID            string `json:"cve_id"`
	VendorProject    string `json:"vendor_project,omitempty"`
	Product          string `json:"product,omitempty"`
	DateAdded        string `json:"date_added,omitempty"`
	ShortDescription string `json:"short_description,omitempty"`
	RequiredAction   string `json:"required_action,omitempty"`
	DueDate          string `json:"due_date,omitempty"`
	KnownRansomware  string `json:"known_ransomware,omitempty"`
}
