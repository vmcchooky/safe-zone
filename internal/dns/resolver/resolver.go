package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"

	"safe-zone/internal/correlation"
	"safe-zone/internal/dns/doh"
	"safe-zone/internal/logjson"
	"safe-zone/internal/observability"
	"safe-zone/internal/ratelimit"
	"safe-zone/internal/risk"
)

const (
	BlockStrategySinkhole = "sinkhole"
	BlockStrategyNXDomain = "nxdomain"
	BlockStrategyRefused  = "refused"
	BlockStrategyNullIP   = "nullip"
)

// maxCNAMEPolicyChecks bounds how many CNAME targets of one upstream
// response are policy-evaluated. Real chains are a handful of records; an
// unbounded walk lets a hostile upstream turn one query into N full
// evaluations. Overflow fails closed: truncated evaluation must not
// silently allow, so callers surface SERVFAIL like any upstream failure.
const maxCNAMEPolicyChecks = 8

type Config struct {
	BlockPageIP    string
	BlockStrategy  string
	DNSTTL         uint32
	DeploymentTier string
	// MaxConcurrentQueries bounds in-flight ResolveQuery calls across all
	// transports. Per-IP rate limits stop single actors; this stops the
	// aggregate from exhausting goroutines and upstream budget under a
	// distributed flood. Zero means DefaultMaxConcurrentQueries.
	MaxConcurrentQueries int
}

// DefaultMaxConcurrentQueries caps simultaneous DNS evaluations. A
// household bursts dozens of queries; hundreds concurrent is already far
// beyond legitimate peaks on a budget VPS.
const DefaultMaxConcurrentQueries = 256

// Resolver là tầng chính sách trung tâm: mọi transport (DoH, DoT) đều gọi
// ResolveQuery thay vì tự triển khai logic chặn/forward/uncloak riêng.
type Resolver struct {
	Risk      *risk.Service
	Metrics   *observability.Registry
	Upstreams *doh.UpstreamResolver
	Config    Config
	// DotLimiter giới hạn tần suất riêng cho transport DoT; DoH đi qua
	// TieredMiddleware ở cạnh HTTP.
	DotLimiter *ratelimit.Limiter
	inflight   atomic.Int64
}

func New(riskService *risk.Service, metrics *observability.Registry, upstreams *doh.UpstreamResolver, cfg Config, dotLimiter *ratelimit.Limiter) *Resolver {
	if cfg.BlockStrategy == "" {
		cfg.BlockStrategy = BlockStrategySinkhole
	}
	return &Resolver{
		Risk:       riskService,
		Metrics:    metrics,
		Upstreams:  upstreams,
		Config:     cfg,
		DotLimiter: dotLimiter,
	}
}

// ResolveQuery thực thi pipeline xử lý truy vấn dùng chung cho mọi transport:
// đánh giá policy theo client → chặn theo block strategy → forward upstream
// DoH → uncloaking CNAME. Trả về response hoàn chỉnh, hoặc error khi upstream
// thất bại (transport sẽ phản hồi SERVFAIL theo đúng chuẩn của từng giao thức).
func (r *Resolver) ResolveQuery(ctx context.Context, query *dns.Msg, client doh.ClientInfo) (*dns.Msg, error) {
	maxInflight := r.Config.MaxConcurrentQueries
	if maxInflight <= 0 {
		maxInflight = DefaultMaxConcurrentQueries
	}
	if r.inflight.Add(1) > int64(maxInflight) {
		r.inflight.Add(-1)
		logjson.Warn("dns concurrency limit exceeded", correlation.Fields(ctx, map[string]any{
			"service": "dns-resolver",
			"limit":   maxInflight,
		}))
		return nil, fmt.Errorf("too many concurrent dns queries (limit %d)", maxInflight)
	}
	defer r.inflight.Add(-1)

	if len(query.Question) == 0 {
		// An empty question has no name to apply policy to, and the indexing
		// below would panic. Both current callers guard this, but ResolveQuery
		// is exported and implements a public interface, so the check belongs
		// at its own boundary rather than in every caller.
		if r.Metrics != nil {
			r.Metrics.IncCounter("malformed_dns_queries_total")
		}
		return nil, errors.New("dns query has no question")
	}

	questionDomain := strings.TrimSuffix(query.Question[0].Name, ".")
	riskClient := risk.ClientInfo{IP: client.IP, ClientID: client.ClientID}

	policy := r.Risk.Policy(ctx, questionDomain, riskClient)
	if policy.Policy == "block" {
		return r.BlockedDNSMessage(query)
	}

	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}

	responseWire, err := r.ForwardDoH(ctx, wire)
	if err != nil {
		if r.Metrics != nil {
			r.Metrics.IncCounter("upstream_doh_failures_total")
		}
		logjson.Warn("upstream DoH failed", correlation.Fields(ctx, map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
		}))
		return nil, err
	}

	responseMsg := new(dns.Msg)
	if err := responseMsg.Unpack(responseWire); err != nil {
		return nil, err
	}

	// The upstream reply is untrusted input. A response whose ID or question
	// does not match what was asked is either a misbehaving resolver or an
	// attempt to slip an answer past the policy check that follows, and neither
	// is something to forward to the client.
	if err := validateUpstreamResponse(query, responseMsg); err != nil {
		if r.Metrics != nil {
			r.Metrics.IncCounter("upstream_doh_mismatched_total")
		}
		logjson.Warn("upstream DoH response did not match the query", correlation.Fields(ctx, map[string]any{
			"service": "dns-resolver",
			"domain":  questionDomain,
			"error":   err.Error(),
		}))
		return nil, err
	}

	// CNAME uncloaking: the policy has to be applied to the final target of a
	// CNAME, not just to the name the client asked for. Every section is
	// scanned, not only Answer: a CNAME placed in Additional or Authority by a
	// resolver that happens to do so is still a redirection the client will
	// follow, and restricting the walk to Answer meant such a chain was never
	// policy-checked at all.
	checked := 0
	for _, section := range [][]dns.RR{responseMsg.Answer, responseMsg.Ns, responseMsg.Extra} {
		for _, answer := range section {
			cname, ok := answer.(*dns.CNAME)
			if !ok || cname.Target == "" {
				continue
			}
			checked++
			if checked > maxCNAMEPolicyChecks {
				logjson.Warn("cname policy check limit exceeded", correlation.Fields(ctx, map[string]any{
					"service": "dns-resolver",
					"domain":  questionDomain,
					"checked": checked,
				}))
				return nil, fmt.Errorf("cname policy check limit exceeded (%d targets)", maxCNAMEPolicyChecks)
			}
			cnamePolicy := r.Risk.Policy(ctx, strings.TrimSuffix(cname.Target, "."), riskClient)
			if cnamePolicy.Policy == "block" {
				return r.BlockedDNSMessage(query)
			}
		}
	}

	return responseMsg, nil
}

// validateUpstreamResponse checks that a reply belongs to the query that was
// sent. Without it, a resolver that returns a mismatched message has its
// contents forwarded to the client after the policy check above, so the
// uncloaking guarantee applies to a message that was never asked for.
func validateUpstreamResponse(query, response *dns.Msg) error {
	if response == nil {
		return errors.New("nil upstream response")
	}
	if !response.Response {
		return errors.New("upstream message is not a response")
	}
	if response.Id != query.Id {
		return fmt.Errorf("upstream id %d does not match query id %d", response.Id, query.Id)
	}
	if query.Opcode == dns.OpcodeQuery && response.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("upstream opcode %d does not match query opcode %d", response.Opcode, query.Opcode)
	}
	if len(response.Question) != 1 || len(query.Question) != 1 {
		return fmt.Errorf("upstream question count %d does not match query count %d",
			len(response.Question), len(query.Question))
	}
	// Case-insensitive per RFC 4343: 0x20 randomisation exists precisely so
	// names differing only in case are still the same question.
	if !strings.EqualFold(response.Question[0].Name, query.Question[0].Name) {
		return fmt.Errorf("upstream question %q does not match query %q",
			response.Question[0].Name, query.Question[0].Name)
	}
	if response.Question[0].Qtype != query.Question[0].Qtype ||
		response.Question[0].Qclass != query.Question[0].Qclass {
		return errors.New("upstream question type or class does not match")
	}
	return nil
}

func (r *Resolver) EffectiveBlockStrategy() string {
	if r.Config.BlockStrategy == "" {
		return BlockStrategySinkhole
	}
	return r.Config.BlockStrategy
}

func (r *Resolver) BlockIPv4() net.IP {
	if r.EffectiveBlockStrategy() == BlockStrategyNullIP {
		return net.IPv4(0, 0, 0, 0)
	}
	return net.ParseIP(r.Config.BlockPageIP).To4()
}

func (r *Resolver) BlockIPv6() net.IP {
	if r.EffectiveBlockStrategy() == BlockStrategyNullIP {
		return net.IPv6zero
	}
	return net.ParseIP(r.Config.BlockPageIP).To16()
}

func (r *Resolver) BlockedDNSMessage(query *dns.Msg) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true

	switch r.EffectiveBlockStrategy() {
	case BlockStrategyNXDomain:
		response.Rcode = dns.RcodeNameError
		return response, nil
	case BlockStrategyRefused:
		response.Rcode = dns.RcodeRefused
		return response, nil
	}

	for _, question := range query.Question {
		switch question.Qtype {
		case dns.TypeA:
			ip := r.BlockIPv4()
			if ip == nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: question.Qclass, Ttl: r.Config.DNSTTL},
				A:   ip,
			})
		case dns.TypeAAAA:
			ip := r.BlockIPv6()
			if ip == nil {
				continue
			}
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: question.Qclass, Ttl: r.Config.DNSTTL},
				AAAA: ip,
			})
		}
	}

	return response, nil
}

func (r *Resolver) ForwardDoH(ctx context.Context, wire []byte) ([]byte, error) {
	response, _, err := r.Upstreams.Forward(ctx, wire)
	return response, err
}

// SendServfail trả lời SERVFAIL trực tiếp trên transport DNS (DoT).
func SendServfail(w dns.ResponseWriter, req *dns.Msg) {
	response := new(dns.Msg)
	response.SetRcode(req, dns.RcodeServerFailure)
	response.RecursionAvailable = true
	_ = w.WriteMsg(response)
}
