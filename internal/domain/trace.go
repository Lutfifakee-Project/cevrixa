package domain

// TraceStep is one reconstructable stage of a detection decision. The trace is
// the ordered reasoning path behind a verdict, so a reader can inspect how a
// decision was reached instead of trusting only its result.
type TraceStep struct {
	// Name is the stage, for example "resolve identity" or "evaluate
	// applicability". It is stable so the step can be matched across records.
	Name string `json:"name"`
	// Detail is the human-readable outcome of the stage for this target.
	Detail string `json:"detail,omitempty"`
	// Status is one of "ok", "skipped", "warn", or "fail". It describes how
	// the stage ended, not the final decision.
	Status string `json:"status"`
}

// Trace is the ordered list of steps behind one decision.
type Trace struct {
	Steps []TraceStep `json:"steps,omitempty"`
}

// Trace status values.
const (
	TraceOK      = "ok"
	TraceSkipped = "skipped"
	TraceWarn    = "warn"
	TraceFail    = "fail"
)

// Add appends one step to the trace.
func (t *Trace) Add(name, status, detail string) {
	t.Steps = append(t.Steps, TraceStep{Name: name, Status: status, Detail: detail})
}
