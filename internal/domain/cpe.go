package domain

import (
	"fmt"
	"strings"
)

const (
	cpe23Prefix = "cpe:2.3:"
	cpe23Fields = 13
)

type CPE struct {
	Part      string `json:"part"`
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Update    string `json:"update"`
	Edition   string `json:"edition"`
	Language  string `json:"language"`
	SWEdition string `json:"sw_edition"`
	TargetSW  string `json:"target_sw"`
	TargetHW  string `json:"target_hw"`
	Other     string `json:"other"`
}

func ParseCPE(s string) (CPE, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return CPE{}, fmt.Errorf("cpe: empty input")
	}
	if !strings.HasPrefix(t, cpe23Prefix) {
		return CPE{}, fmt.Errorf("cpe: only CPE 2.3 format is supported, got %q", s)
	}
	parts := strings.Split(t, ":")
	if len(parts) != cpe23Fields {
		return CPE{}, fmt.Errorf("cpe: expected %d fields, got %d", cpe23Fields, len(parts))
	}
	return CPE{
		Part:      parts[2],
		Vendor:    parts[3],
		Product:   parts[4],
		Version:   parts[5],
		Update:    parts[6],
		Edition:   parts[7],
		Language:  parts[8],
		SWEdition: parts[9],
		TargetSW:  parts[10],
		TargetHW:  parts[11],
		Other:     parts[12],
	}, nil
}

func (c CPE) String() string {
	return strings.Join([]string{
		"cpe", "2.3",
		c.Part, c.Vendor, c.Product, c.Version, c.Update,
		c.Edition, c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other,
	}, ":")
}

func (c CPE) IsWildcard(field string) bool {
	switch field {
	case "version":
		return c.Version == "" || c.Version == "*" || c.Version == "-"
	}
	return false
}
