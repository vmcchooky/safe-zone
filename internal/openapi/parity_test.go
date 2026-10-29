// Package openapi guards the contract between the registered HTTP routes and
// docs/openapi/safe-zone.yaml. The route tables in internal/api/server and
// internal/dns/server are the source of truth for what the services serve;
// this test diffs them against the spec in both directions and checks that
// each operation's security declaration matches the route's auth label.
package openapi

import (
	"os"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	apiser "safe-zone/internal/api/server"
	dnser "safe-zone/internal/dns/server"
)

const specPath = "../../docs/openapi/safe-zone.yaml"

// isOperationKey reports whether a path-item key is an OpenAPI operation.
func isOperationKey(key string) bool {
	switch strings.ToLower(key) {
	case "get", "post", "put", "delete", "patch", "head", "options", "trace":
		return true
	}
	return false
}

type specOperation struct {
	method   string
	secured  bool
	optional bool
}

func loadSpec(t *testing.T) map[string][]specOperation {
	t.Helper()

	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}

	var doc struct {
		Paths map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	if len(doc.Paths) == 0 {
		t.Fatalf("spec at %s declares no paths", specPath)
	}

	operations := map[string][]specOperation{}
	for path, node := range doc.Paths {
		if node.Kind != yaml.MappingNode {
			t.Fatalf("spec path %s is not a mapping", path)
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if !isOperationKey(key) {
				continue
			}
			op := node.Content[i+1]
			secured := false
			optional := false
			for j := 0; j+1 < len(op.Content); j += 2 {
				if op.Content[j].Value != "security" {
					continue
				}
				// `security` is a sequence of requirement objects; an empty
				// requirement (`security: [{}]`) marks authentication as
				// optional rather than required.
				sec := op.Content[j+1]
				if sec.Kind != yaml.SequenceNode {
					t.Fatalf("security on %s %s is not a sequence", strings.ToLower(key), path)
				}
				for _, requirement := range sec.Content {
					if len(requirement.Content) == 0 {
						optional = true
						continue
					}
					secured = true
				}
			}
			operations[path] = append(operations[path], specOperation{
				method:   strings.ToLower(key),
				secured:  secured,
				optional: optional,
			})
		}
	}
	return operations
}

type tableRoute struct {
	path string
	auth string
}

func routeTable(t *testing.T) []tableRoute {
	t.Helper()

	out := make([]tableRoute, 0, 64)
	for _, r := range apiser.SpecRoutes() {
		out = append(out, tableRoute{path: r.Path, auth: string(r.Auth)})
	}
	for _, r := range dnser.SpecRoutes() {
		out = append(out, tableRoute{path: r.Path, auth: string(r.Auth)})
	}
	return out
}

func TestOpenAPIMatchesRegisteredRoutes(t *testing.T) {
	spec := loadSpec(t)
	table := routeTable(t)

	// Both services serve some shared paths (/healthz, /readyz, /v1/version,
	// /metrics), and /metrics is admin-gated on core-api but bearer-gated on
	// dns-resolver, so auth labels are collected per path and every label
	// must be satisfied by the spec operations.
	authByPath := map[string][]string{}
	for i, r := range table {
		for j, prev := range table {
			if i != j && r.path == prev.path && r.auth != prev.auth &&
				(r.auth == "public" || prev.auth == "public") {
				t.Fatalf("path %s mixes public and credentialled auth (%s, %s)", r.path, r.auth, prev.auth)
			}
		}
		authByPath[r.path] = append(authByPath[r.path], r.auth)
	}

	// Every registered route must be documented, including its auth label.
	for _, path := range sortedAuthPaths(authByPath) {
		ops, ok := spec[path]
		if !ok {
			t.Errorf("route %s (%s) has no entry in %s", path, strings.Join(authByPath[path], ","), specPath)
			continue
		}
		if len(ops) == 0 {
			t.Errorf("spec path %s declares no operations", path)
			continue
		}
		for _, auth := range authByPath[path] {
			switch auth {
			case "auth", "admin", "admin-mutation", "bearer-admin":
				for _, op := range ops {
					if !op.secured {
						t.Errorf("%s %s is %s but its spec operation declares no security", op.method, path, auth)
					}
				}
			case "public", "attach-identity":
				for _, op := range ops {
					if op.secured && !op.optional {
						t.Errorf("%s %s is %s but its spec operation requires credentials", op.method, path, auth)
					}
				}
			default:
				t.Errorf("unknown auth label %q on route %s", auth, path)
			}
		}
	}

	// Every documented path must exist in a route table. The tables cover
	// all API routes on both services, so the spec may not document anything
	// the routers do not serve.
	specPaths := make([]string, 0, len(spec))
	for path := range spec {
		specPaths = append(specPaths, path)
	}
	sort.Strings(specPaths)
	for _, path := range specPaths {
		if _, ok := authByPath[path]; !ok {
			t.Errorf("spec documents %s but no router registers it", path)
		}
	}
}

func sortedAuthPaths(authByPath map[string][]string) []string {
	paths := make([]string, 0, len(authByPath))
	for path := range authByPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
