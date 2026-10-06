package output

import (
	"encoding/json"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

type scanJSON struct {
	Reports []domain.Report `json:"reports"`
}

// scanSeparator is the blank-line-delimited rule printed between reports in a
// multi-report human render: newline, ---, newline, newline.
var scanSeparator = []byte{10, 45, 45, 45, 10, 10}

func RenderScanHuman(w io.Writer, reports []domain.Report) error {
	return RenderScanHumanWithOptions(w, reports, RenderOptions{})
}

// RenderScanHumanWithOptions renders a list of reports for a human, honouring
// the same Verbose/Quiet options as a single-target render so that scan and
// sbom behave like detect.
func RenderScanHumanWithOptions(w io.Writer, reports []domain.Report, opts RenderOptions) error {
	for i, r := range reports {
		if opts.Quiet {
			if err := renderHumanQuiet(w, r); err != nil {
				return err
			}
			continue
		}
		if i > 0 {
			if _, err := w.Write(scanSeparator); err != nil {
				return err
			}
		}
		if err := RenderHumanWithOptions(w, r, opts); err != nil {
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
