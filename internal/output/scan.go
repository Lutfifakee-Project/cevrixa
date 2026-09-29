package output

import (
	"encoding/json"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type scanJSON struct {
	Reports []domain.Report `json:"reports"`
}

func RenderScanHuman(w io.Writer, reports []domain.Report) error {
	for i, r := range reports {
		if i > 0 {
			if _, err := io.WriteString(w, "\n---\n\n"); err != nil {
				return err
			}
		}
		if err := RenderHuman(w, r); err != nil {
			return err
		}
	}
	return nil
}

func RenderScanJSON(w io.Writer, reports []domain.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(scanJSON{Reports: reports})
}

func RenderScanJSONL(w io.Writer, reports []domain.Report) error {
	for _, r := range reports {
		if err := RenderJSONL(w, r); err != nil {
			return err
		}
	}
	return nil
}

func RenderScanSARIF(w io.Writer, reports []domain.Report, toolVersion string) error {
	return RenderSARIFMulti(w, reports, toolVersion)
}
