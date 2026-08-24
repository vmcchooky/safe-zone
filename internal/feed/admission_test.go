package feed

import (
	"strings"
	"testing"
)

func TestPlanAdmissionCorroboratesDistinctURLResources(t *testing.T) {
	plan, err := PlanAdmission(strings.NewReader(strings.Join([]string{
		"https://single.test/login",
		"https://repeated.test/login",
		"https://repeated.test/reset",
		"https://root.test/",
		"http://192.0.2.10/payload",
		"domain.test",
	}, "\n")), AdmissionShadow)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(plan.Contextual, ","); got != "single.test" {
		t.Fatalf("unexpected contextual hosts: %s", got)
	}
	if got := strings.Join(plan.Authoritative, ","); got != "192.0.2.10,domain.test,repeated.test,root.test" {
		t.Fatalf("unexpected authoritative hosts: %s", got)
	}
	if plan.Stats.AuthoritativeHosts != 4 || plan.Stats.ContextualHosts != 1 || plan.Stats.CorroboratedURLHosts != 1 {
		t.Fatalf("unexpected admission stats: %#v", plan.Stats)
	}
}

func TestPlanAdmissionDoesNotCorroborateDuplicateResource(t *testing.T) {
	plan, err := PlanAdmission(strings.NewReader("https://single.test/login\nhttps://single.test/login\n"), AdmissionFilter)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Authoritative) != 0 || len(plan.Contextual) != 1 {
		t.Fatalf("unexpected plan: %#v", plan)
	}
}

func TestNormalizeAdmissionModeRejectsUnknownValue(t *testing.T) {
	if _, err := NormalizeAdmissionMode("aggressive"); err == nil {
		t.Fatal("expected unsupported admission mode error")
	}
}
