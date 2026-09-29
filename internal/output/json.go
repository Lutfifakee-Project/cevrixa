package output

import (
	"encoding/json"
	"io"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
)

func RenderJSON(w io.Writer, r domain.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
func newJSONEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc
}
