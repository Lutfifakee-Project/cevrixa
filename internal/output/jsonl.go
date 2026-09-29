package output

import (
	"encoding/json"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type jsonlLine struct {
	Target  domain.Target  `json:"target"`
	Finding domain.Finding `json:"finding"`
}

func RenderJSONL(w io.Writer, r domain.Report) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for _, f := range r.Findings {
		line := jsonlLine{Target: r.Target, Finding: f}
		if err := enc.Encode(line); err != nil {
			return err
		}
	}
	return nil
}
