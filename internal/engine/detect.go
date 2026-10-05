package engine

import (
	"fmt"

	"github.com/Lutfifakee-Project/cevrixa/internal/domain"
	"github.com/Lutfifakee-Project/cevrixa/internal/matcher"
	"github.com/Lutfifakee-Project/cevrixa/internal/resolver"
	"github.com/Lutfifakee-Project/cevrixa/internal/store"
)

type Options struct {
	KEV   map[string]domain.KEVInfo
	Store *store.Store
	// Trace asks detection to record the reasoning path behind the decision.
	Trace bool
}

func Detect(target domain.Target, opts Options) (domain.Report, error) {
	if target.PURL != "" {
		return detectByPURL(target, opts)
	}
	return detectByCPE(target, opts)
}

func detectByCPE(target domain.Target, opts Options) (domain.Report, error) {
	trace := domain.Trace{}

	r := resolver.New()
	res, err := r.Resolve(target)
	if err != nil {
		return domain.Report{}, err
	}
	target.ResolvedCPE = res.CPE
	trace.Add("resolve identity", traceStatus(res.CPE != ""), resolveDetail(target, res))

	vulns, dataset, err := loadVulnerabilities(opts)
	if err != nil {
		return domain.Report{}, err
	}
	trace.Add("candidate discovery", domain.TraceOK, fmt.Sprintf("searched %d record(s)", len(vulns)))

	report := domain.Report{Target: target, Findings: []domain.Finding{}, Dataset: dataset}
	if target.ResolvedCPE == "" {
		trace.Add("evaluate applicability", domain.TraceSkipped, "identity was not resolved, so no applicability was evaluated")
		report.Trace = traceIf(opts, trace)
		return report, nil
	}

	targetCPE, err := domain.ParseCPE(target.ResolvedCPE)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse resolved CPE: %w", err)
	}

	findings := []domain.Finding{}
	matched, undecided := 0, 0
	for _, v := range vulns {
		mr, err := matcher.MatchCPE(targetCPE, v)
		if err != nil {
			continue
		}
		if !mr.Matched && !mr.Undecided {
			continue
		}
		if mr.Undecided {
			undecided++
		} else {
			matched++
		}
		f := buildFinding(targetCPE, v, mr, enrichmentsFor(opts, v.ID))
		attachKEV(&f, v.ID, opts)
		attachEnrichment(&f, v.ID, opts)
		attachEPSS(&f, v.ID, opts)
		f.Priority = domain.ComputePriority(f)
		findings = append(findings, f)
	}
	report.Findings = findings
	trace.Add("evaluate applicability", domain.TraceOK,
		fmt.Sprintf("matched %d, inconclusive %d, not affected %d", matched, undecided, len(vulns)-matched-undecided))
	trace.Add("decide", traceStatus(matched > 0), decideDetail(matched, undecided, len(findings)))
	report.Trace = traceIf(opts, trace)

	return report, nil
}

func detectByPURL(target domain.Target, opts Options) (domain.Report, error) {
	trace := domain.Trace{}

	purl, err := domain.ParsePURL(target.PURL)
	if err != nil {
		return domain.Report{}, fmt.Errorf("engine: parse PURL: %w", err)
	}
	if purl.Version == "" {
		return domain.Report{}, fmt.Errorf("engine: PURL must include a version")
	}
	trace.Add("resolve identity", domain.TraceOK, "package "+purl.Name+"@"+purl.Version+" ("+purl.Type+")")

	vulns, dataset, err := loadVulnerabilities(opts)
	if err != nil {
		return domain.Report{}, err
	}
	trace.Add("candidate discovery", domain.TraceOK, fmt.Sprintf("searched %d record(s)", len(vulns)))

	findings := []domain.Finding{}
	matched, undecided := 0, 0
	for _, v := range vulns {
		if len(v.PackageApplicability) == 0 {
			continue
		}
		pr, ok := matchPackage(purl, v)
		if !ok {
			continue
		}
		if !pr.Matched && !pr.Undecided {
			continue
		}
		if pr.Undecided {
			undecided++
		} else {
			matched++
		}
		f := buildPackageFinding(purl, v, pr, enrichmentsFor(opts, v.ID))
		attachKEV(&f, v.ID, opts)
		attachEnrichment(&f, v.ID, opts)
		attachEPSS(&f, v.ID, opts)
		f.Priority = domain.ComputePriority(f)
		findings = append(findings, f)
	}
	trace.Add("evaluate applicability", domain.TraceOK,
		fmt.Sprintf("matched %d, inconclusive %d", matched, undecided))
	trace.Add("decide", traceStatus(matched > 0), decideDetail(matched, undecided, len(findings)))

	return domain.Report{Target: target, Findings: findings, Dataset: dataset, Trace: traceIf(opts, trace)}, nil
}

// traceIf returns the trace only when the caller asked for one, so a normal
// detection does not carry reasoning noise it never requested.
func traceIf(opts Options, t domain.Trace) domain.Trace {
	if !opts.Trace {
		return domain.Trace{}
	}
	return t
}

func traceStatus(ok bool) string {
	if ok {
		return domain.TraceOK
	}
	return domain.TraceWarn
}

func resolveDetail(target domain.Target, res resolver.Result) string {
	if target.ResolvedCPE != "" {
		return "resolved to " + target.ResolvedCPE
	}
	if res.CPE != "" {
		return "resolved to " + res.CPE
	}
	return "target identity could not be resolved"
}

func decideDetail(matched, undecided, findings int) string {
	switch {
	case matched > 0:
		return fmt.Sprintf("%d affected finding(s)", matched)
	case undecided > 0:
		return fmt.Sprintf("%d inconclusive finding(s)", undecided)
	default:
		return "no affected or inconclusive finding"
	}
}

// enrichmentsFor returns every stored enrichment for a vulnerability, from all
// sources. Passing them into correlation is what makes cross-source conflicts
// reachable; without them the conflict machinery never has two sources to
// compare.
func enrichmentsFor(opts Options, vulnID string) []domain.Enrichment {
	if opts.Store == nil || vulnID == "" {
		return nil
	}
	list, err := opts.Store.ListEnrichments(vulnID)
	if err != nil {
		return nil
	}
	return list
}

func attachKEV(f *domain.Finding, cveID string, opts Options) {
	if opts.KEV == nil {
		return
	}
	if info, ok := opts.KEV[cveID]; ok {
		infoCopy := info
		f.KnownExploited = &infoCopy
	}
}

func attachEnrichment(f *domain.Finding, cveID string, opts Options) {
	if opts.Store == nil {
		return
	}
	e, err := opts.Store.GetEnrichmentAny(cveID, "")
	if err != nil {
		return
	}
	f.Enrichment = &e
}

// attachEPSS copies a stored EPSS score onto the finding's risk, copying the
// Risk struct first so the vulnerability's shared pointer is never mutated.
// EPSS ranks a finding; it never changes applicability.
func attachEPSS(f *domain.Finding, cveID string, opts Options) {
	if opts.Store == nil || cveID == "" {
		return
	}
	r, ok, err := opts.Store.GetEPSS(cveID)
	if err != nil || !ok {
		return
	}
	if f.Risk == nil {
		f.Risk = &domain.Risk{}
	} else {
		cp := *f.Risk
		f.Risk = &cp
	}
	f.Risk.EPSS = r.Score
	f.Risk.EPSSPercentile = r.Percentile
}
