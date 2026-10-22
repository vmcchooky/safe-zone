package main

import (
	"testing"
)

func TestFeedConfigurationProblemAcceptsTheDaemon(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	if err := feedConfigurationProblem([]string{"https://a.example.test/list.txt"}, false, "https://a.example.test/list.txt"); err != nil {
		t.Fatalf("the daemon syncs the feed, so this configuration must be accepted: %v", err)
	}
}

func TestFeedConfigurationProblemAcceptsTheAgent(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	if err := feedConfigurationProblem([]string{"https://a.example.test/list.txt"}, true, ""); err != nil {
		t.Fatalf("the agent task syncs the feed, so this configuration must be accepted: %v", err)
	}
}

func TestFeedConfigurationProblemRefusesNoSource(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	err := feedConfigurationProblem(nil, true, "https://a.example.test/list.txt")
	if err == nil {
		t.Fatal("a deployment with no feed source must be refused in production")
	}
}

func TestFeedConfigurationProblemRefusesASourceNobodySyncs(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	err := feedConfigurationProblem([]string{"https://a.example.test/list.txt"}, false, "")
	if err == nil {
		t.Fatal("a configured source that nothing syncs must be refused in production")
	}
}

func TestFeedConfigurationProblemIsNotAppliedOutsideProduction(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "local")

	if err := feedConfigurationProblem(nil, false, ""); err != nil {
		t.Fatalf("a local run without a feed must be accepted: %v", err)
	}
}
