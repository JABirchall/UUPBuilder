package probes

import (
	"errors"
	"fmt"
	"reflect"

	"uupbuilder/internal/model"
)

// ArchitectureCoverage records a required logical pair and its actual witness.
// Portability acceptance never changes an observed Case or Evidence host.
type ArchitectureCoverage struct {
	RequiredCaseID string             `json:"required_case_id"`
	RequiredHost   HostRequirement    `json:"required_host"`
	Target         model.Architecture `json:"target"`
	WitnessCaseID  string             `json:"witness_case_id"`
	WitnessHost    ObservedHost       `json:"witness_host"`
	Basis          string             `json:"basis"`
}

// ValidateArchitectureCoverage applies the user-approved single-host rule above
// strict observed-record validation. Successful Windows 386/amd64/arm64 builds
// remain a separate required gate; this function neither runs nor attests them.
// As with ValidateEvidence, synthetic records can test this contract but cannot
// establish that execution occurred or that retained artifacts exist.
func ValidateArchitectureCoverage(required []Case, observed []Evidence) ([]ArchitectureCoverage, error) {
	if len(required) == 0 {
		return nil, errors.New("architecture coverage: empty required set")
	}
	requirements := map[string]Case{}
	for _, c := range required {
		if _, duplicate := requirements[c.ID]; duplicate {
			return nil, errors.New("architecture coverage: duplicate requirement")
		}
		if err := c.Validate(); err != nil {
			return nil, fmt.Errorf("architecture coverage: case %s: %w", c.ID, err)
		}
		for _, pending := range c.Pending {
			if pending.Code != "native-host-not-established" {
				return nil, fmt.Errorf("architecture coverage: case %s has unresolved functional prerequisite %s", c.ID, pending.Code)
			}
		}
		requirements[c.ID] = c
	}
	// Reports may be produced by separate runs. Group their measured host facts,
	// not incidental report IDs. This is no independent physical-host attestation.
	type hostFacts struct {
		OS   string
		Host model.Host
	}
	groups := map[hostFacts][]Evidence{}
	var hosts []hostFacts
	seen := map[string]bool{}
	for _, e := range observed {
		c, ok := requirements[e.CaseID]
		if !ok || seen[e.CaseID] {
			return nil, fmt.Errorf("architecture coverage: unexpected/duplicate witness %s", e.CaseID)
		}
		seen[e.CaseID] = true
		if err := ValidateEvidence([]Case{c}, []Evidence{e}); err != nil {
			return nil, fmt.Errorf("architecture coverage: witness %s: %w", c.ID, err)
		}
		key := hostFacts{e.Host.OS, e.Host.Host}
		if _, ok := groups[key]; !ok {
			hosts = append(hosts, key)
		}
		groups[key] = append(groups[key], e)
	}
	for _, host := range hosts {
		coverage := make([]ArchitectureCoverage, 0, len(required))
		for _, c := range required {
			for _, e := range groups[host] {
				if !equivalentFunctionalCase(c, requirements[e.CaseID]) {
					continue
				}
				basis := "portability-accepted"
				if c.ID == e.CaseID {
					basis = "observed"
				}
				coverage = append(coverage, ArchitectureCoverage{c.ID, c.Host, c.Target, e.CaseID, e.Host, basis})
				break
			}
		}
		if len(coverage) == len(required) {
			return coverage, nil
		}
	}
	return nil, errors.New("architecture coverage: no single observed host has complete required target/source/operation/output proof")
}

// Native component bytes/closure and host architecture labels are covered by
// portability acceptance only for counterparts. Each actual witness still needs
// its own full ValidateReady and exact ValidateEvidence component bindings.
func equivalentFunctionalCase(a, b Case) bool {
	return a.Gate == b.Gate && a.Host.OS == b.Host.OS && a.Host.MinimumBuild == b.Host.MinimumBuild &&
		a.Target == b.Target && a.SourceFamily == b.SourceFamily && a.Source == b.Source &&
		a.RevisionProvenance == b.RevisionProvenance && reflect.DeepEqual(a.Inputs, b.Inputs) &&
		reflect.DeepEqual(a.Operations, b.Operations) && reflect.DeepEqual(a.Algorithms, b.Algorithms) &&
		reflect.DeepEqual(a.Expected, b.Expected)
}

func currentHostCases(required []Case, host ObservedHost) ([]Case, error) {
	if host.OS != "windows" || host.Host.WindowsBuild < 10240 ||
		!oneOf(string(host.Host.NativeArchitecture), "x86", "amd64", "arm64") ||
		host.Host.ProcessArchitecture != host.Host.NativeArchitecture {
		return nil, errors.New("architecture coverage: actual native Windows 10+ host required")
	}
	var selected []Case
	for _, c := range required {
		if c.Host.OS == host.OS && c.Host.MinimumBuild <= host.Host.WindowsBuild &&
			c.Host.NativeArchitecture == host.Host.NativeArchitecture && c.Host.ProcessArchitecture == host.Host.ProcessArchitecture {
			selected = append(selected, c)
		}
	}
	if len(selected) == 0 {
		return nil, errors.New("architecture coverage: no applicable current-host cases")
	}
	return selected, nil
}
