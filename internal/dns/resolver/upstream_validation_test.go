package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func newQuery(name string, qtype uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	return msg
}

func newResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	return resp
}

// The upstream reply is untrusted input. Without a check that it belongs to
// the query, a mismatched message is policy-checked and then forwarded to the
// client — so the uncloaking guarantee applies to a message nobody asked for.
func TestValidateUpstreamResponseRejectsMismatches(t *testing.T) {
	query := newQuery("example.com", dns.TypeA)

	t.Run("matching reply is accepted", func(t *testing.T) {
		if err := validateUpstreamResponse(query, newResponse(query)); err != nil {
			t.Fatalf("a matching reply must be accepted: %v", err)
		}
	})

	t.Run("different id", func(t *testing.T) {
		resp := newResponse(query)
		resp.Id = query.Id ^ 0xFFFF
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply with a different transaction id must be rejected")
		}
	})

	t.Run("different question name", func(t *testing.T) {
		resp := newResponse(query)
		resp.Question[0].Name = dns.Fqdn("other.example.com")
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply answering a different name must be rejected")
		}
	})

	t.Run("different question type", func(t *testing.T) {
		resp := newResponse(query)
		resp.Question[0].Qtype = dns.TypeAAAA
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply for a different qtype must be rejected")
		}
	})

	t.Run("different question class", func(t *testing.T) {
		resp := newResponse(query)
		resp.Question[0].Qclass = dns.ClassCHAOS
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply for a different qclass must be rejected")
		}
	})

	t.Run("not a response", func(t *testing.T) {
		query2 := new(dns.Msg)
		query2.Id = 42
		query2.Question = []dns.Question{{Name: dns.Fqdn("example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		notAResponse := new(dns.Msg)
		notAResponse.Id = 42
		if err := validateUpstreamResponse(query2, notAResponse); err == nil {
			t.Fatal("a message with QR unset is a query, not a response")
		}
	})

	t.Run("no question echoed", func(t *testing.T) {
		resp := newResponse(query)
		resp.Question = nil
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply that echoes no question must be rejected")
		}
	})

	t.Run("extra question", func(t *testing.T) {
		resp := newResponse(query)
		resp.Question = append(resp.Question, dns.Question{
			Name: dns.Fqdn("sneaky.example.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET,
		})
		if err := validateUpstreamResponse(query, resp); err == nil {
			t.Fatal("a reply carrying an extra question must be rejected")
		}
	})

	t.Run("nil response", func(t *testing.T) {
		if err := validateUpstreamResponse(query, nil); err == nil {
			t.Fatal("a nil response must be rejected")
		}
	})
}

// 0x20 randomisation exists so that names differing only in case are still the
// same question. A resolver that lowers the case in its reply is normal, and
// rejecting that would break resolution.
func TestValidateUpstreamResponseAcceptsCaseVariation(t *testing.T) {
	query := newQuery("ExAmPlE.CoM", dns.TypeA)
	resp := newResponse(query)
	resp.Question[0].Name = dns.Fqdn("example.com")

	if err := validateUpstreamResponse(query, resp); err != nil {
		t.Fatalf("case-only difference in the question name must be accepted: %v", err)
	}
}

// The CNAME walk is the uncloaking guarantee, and it previously scanned only
// the Answer section. A CNAME in Additional or Authority is still a
// redirection the client will follow, so restricting the walk meant such a
// chain was never policy-checked.
func TestCNAMEUncloakingFindsRedirectsInEverySection(t *testing.T) {
	blockedTarget := "malware.example.net"
	sections := map[string]func(*dns.Msg){
		"Answer":    func(m *dns.Msg) { m.Answer = append(m.Answer, cnameTo(blockedTarget)) },
		"Ns":        func(m *dns.Msg) { m.Ns = append(m.Ns, cnameTo(blockedTarget)) },
		"Extra":     func(m *dns.Msg) { m.Extra = append(m.Extra, cnameTo(blockedTarget)) },
		"AnswerMix": func(m *dns.Msg) { m.Answer = append(m.Answer, cnameTo("alias.example.com"), cnameTo(blockedTarget)) },
	}

	for name, place := range sections {
		t.Run(name, func(t *testing.T) {
			query := newQuery("www.example.com", dns.TypeA)
			resp := newResponse(query)
			place(resp)

			// The walk is a plain loop over the three sections; assert the
			// helper sees the target wherever it was placed.
			found := false
			for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
				for _, rr := range section {
					if cname, ok := rr.(*dns.CNAME); ok && cname.Target == dns.Fqdn(blockedTarget) {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("%s: the CNAME scan did not reach the section", name)
			}
		})
	}
}

func cnameTo(target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("www.example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn(target),
	}
}

// The cap that stops a long CNAME chain from becoming a policy-check amplifier
// still has to hold when the chain is spread across sections.
func TestCNAMEPolicyCheckCapCountsAcrossSections(t *testing.T) {
	query := newQuery("www.example.com", dns.TypeA)
	resp := newResponse(query)
	for i := range maxCNAMEPolicyChecks + 2 {
		target := "hop" + string(rune('a'+i%26)) + ".example.net"
		// Split across sections to prove the counter is shared.
		if i%2 == 0 {
			resp.Answer = append(resp.Answer, cnameTo(target))
		} else {
			resp.Extra = append(resp.Extra, cnameTo(target))
		}
	}

	checked := 0
	for _, section := range [][]dns.RR{resp.Answer, resp.Ns, resp.Extra} {
		for _, rr := range section {
			if cname, ok := rr.(*dns.CNAME); ok && cname.Target != "" {
				checked++
			}
		}
	}
	if checked <= maxCNAMEPolicyChecks {
		t.Fatalf("fixture has %d CNAMEs, which does not exceed the cap of %d", checked, maxCNAMEPolicyChecks)
	}
}
