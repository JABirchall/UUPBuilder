package model

type Artifact struct {
	Kind             OutputKind     `json:"kind"`
	Path             string         `json:"path"`
	SHA256           string         `json:"sha256"`
	Size             int64          `json:"size"`
	VerificationPath string         `json:"verification_path"`
	ReportPath       string         `json:"report_path"`
	Source           SourceIdentity `json:"source"`
	PlanDigest       string         `json:"plan_digest"`
}
