package feed

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

type AdmissionMode string

const (
	AdmissionLegacy AdmissionMode = "legacy"
	AdmissionShadow AdmissionMode = "corroborated-url-host-shadow"
	AdmissionFilter AdmissionMode = "corroborated-url-host-filter"
)

type AdmissionStats struct {
	Mode                   AdmissionMode `json:"mode"`
	AuthoritativeHosts     int           `json:"authoritative_hosts"`
	ContextualHosts        int           `json:"contextual_hosts"`
	URLHosts               int           `json:"url_hosts"`
	PathScopedURLHosts     int           `json:"path_scoped_url_hosts"`
	CorroboratedURLHosts   int           `json:"corroborated_url_hosts"`
	AuthoritativeRetention float64       `json:"authoritative_retention"`
}

type AdmissionPlan struct {
	Authoritative []string       `json:"authoritative"`
	Contextual    []string       `json:"contextual"`
	ParseStats    ParseStats     `json:"parse_stats"`
	Stats         AdmissionStats `json:"admission_stats"`
}

type admissionState struct {
	authoritative bool
	urlSeen       bool
	pathScoped    bool
	resourceSeen  bool
	firstResource [32]byte
	corroborated  bool
}

func NormalizeAdmissionMode(value string) (AdmissionMode, error) {
	mode := AdmissionMode(strings.TrimSpace(value))
	if mode == "" {
		return AdmissionLegacy, nil
	}
	switch mode {
	case AdmissionLegacy, AdmissionShadow, AdmissionFilter:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported feed admission mode %q", value)
	}
}

// PlanAdmission classifies whole-domain evidence as authoritative and demotes
// singleton path-scoped URL hosts to contextual evidence. A second distinct URL
// resource corroborates the host. IP URL indicators remain authoritative because
// their address is already the narrowest host-level identity available here.
func PlanAdmission(r io.Reader, mode AdmissionMode) (AdmissionPlan, error) {
	mode, err := NormalizeAdmissionMode(string(mode))
	if err != nil {
		return AdmissionPlan{}, err
	}
	states := make(map[string]*admissionState)
	var parseStats ParseStats
	err = ParseEachIndicator(r, func(indicator Indicator, _ bool) error {
		state := states[indicator.Domain]
		if state == nil {
			state = &admissionState{}
			states[indicator.Domain] = state
		}
		if indicator.Kind == IndicatorURL {
			state.urlSeen = true
			state.pathScoped = state.pathScoped || indicator.PathScoped
		}
		if mode == AdmissionLegacy || indicator.Kind == IndicatorDomain || !indicator.PathScoped || net.ParseIP(indicator.Domain) != nil {
			state.authoritative = true
			return nil
		}
		if !state.resourceSeen {
			state.firstResource = indicator.resourceFingerprint
			state.resourceSeen = true
			return nil
		}
		if indicator.resourceFingerprint != state.firstResource {
			state.authoritative = true
			state.corroborated = true
		}
		return nil
	}, &parseStats)
	if err != nil {
		return AdmissionPlan{}, err
	}

	plan := AdmissionPlan{ParseStats: parseStats, Stats: AdmissionStats{Mode: mode}}
	for domain, state := range states {
		if state.urlSeen {
			plan.Stats.URLHosts++
		}
		if state.pathScoped {
			plan.Stats.PathScopedURLHosts++
		}
		if state.corroborated {
			plan.Stats.CorroboratedURLHosts++
		}
		if state.authoritative {
			plan.Authoritative = append(plan.Authoritative, domain)
			continue
		}
		plan.Contextual = append(plan.Contextual, domain)
	}
	sort.Strings(plan.Authoritative)
	sort.Strings(plan.Contextual)
	plan.Stats.AuthoritativeHosts = len(plan.Authoritative)
	plan.Stats.ContextualHosts = len(plan.Contextual)
	if parseStats.Valid > 0 {
		plan.Stats.AuthoritativeRetention = float64(len(plan.Authoritative)) / float64(parseStats.Valid)
	}
	return plan, nil
}
