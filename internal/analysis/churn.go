package analysis

import "strings"

// churnProneRoots are namespaces where a tenant label is registered for free
// and without identity verification, then released back into the pool for an
// unrelated party to claim. A feed entry for a tenant leaf under one of these
// roots therefore records "this label was malicious on date X", not "this label
// is permanently malicious": an abandoned campaign keeps its 14-day entry while
// a legitimate user can already hold the same label.
//
// This is deliberately a different concern from selfServiceHostingRoots, which
// governs lexical scoring and shared-apex parent-walk protection. Roots such as
// pages.dev, vercel.app and github.io are self-service but sit behind an account
// signup, so recycling there is far less free-floating and they are not listed
// here. Membership is measured, not guessed: a 4,000-member random sample of
// the live production feed put every root below in the tenant fan-out tail, and
// the hagezi/dns-blocklists hoster inventory independently classifies the same
// classes as repeatedly hosting badware through user-uploaded content.
var churnProneRoots = map[string]bool{
	// Dynamic DNS. The record is under the tenant's control at every
	// moment and the name returns to the pool the moment it is released,
	// so a stale entry can outlive the campaign and catch the next holder.
	"duckdns.org": true, "no-ip.org": true, "no-ip.com": true,
	"ddns.net": true, "hopto.org": true, "serveo.net": true,
	"loclx.net": true, "zapto.org": true, "my.id": true,

	// Free bulk web hosting. Signup is automated and the account is
	// discarded as soon as the campaign ends.
	"000webhostapp.com": true, "000webhost.com": true,
	"weeblysite.com": true, "weebly.com": true, "webflow.io": true,
	"square.site": true, "wixstudio.com": true, "webnode.com": true,
	"ucoz.com": true, "blogspot.com": true,

	// Ephemeral tunnel names. The tunnel endpoint moves; the label does
	// not identify whoever claims it next.
	"ngrok.io": true, "ngrok-free.app": true, "trycloudflare.com": true,

	// Content-addressed gateways. A CID is republishable by anyone and
	// the gateway label carries no ownership claim at all.
	"dweb.link": true, "ipfs.io": true, "ipns.io": true, "cf-ipfs.com": true,
}

// ChurnProneRoot returns the churn-prone root that domain is a tenant leaf of,
// or "" when domain is not under one. The apex itself never matches: a bare
// apex is refused upstream by the public-suffix and shared-serving-host gates,
// so only a tenant leaf can carry the recycling risk this class describes.
func ChurnProneRoot(domain string) string {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if value == "" || strings.HasPrefix(value, "*.") {
		value = strings.TrimPrefix(value, "*.")
	}
	if value == "" {
		return ""
	}
	labels := strings.Split(value, ".")
	// Start at 1 so the apex can never match: a bare root carries no tenant
	// label and is refused upstream by the public-suffix and shared-serving
	// host gates, so only a genuine tenant leaf is at risk of recycling.
	// Walking left to right means the longest matching root wins.
	for i := 1; i < len(labels); i++ {
		root := strings.Join(labels[i:], ".")
		if churnProneRoots[root] {
			return root
		}
	}
	return ""
}

// IsChurnProneTenant reports whether domain is a tenant leaf under a root whose
// labels are recycled. Callers use it to shorten the feed expiry for members
// whose identity does not survive the attacker, never to refuse them: an exact
// feed IOC on a self-service tenant must keep blocking (see the shared-apex
// invariant in the DECISION log).
func IsChurnProneTenant(domain string) bool {
	return ChurnProneRoot(domain) != ""
}
