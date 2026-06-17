package domaintrie

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// childEntry is a label→node pair stored in a sorted slice.
type childEntry struct {
	Label string
	Node  *Node
}

// Node represents a single part (label) of a domain name in the Trie.
// Children are stored in a sorted slice for memory efficiency; binary search
// provides O(log n) lookup which, for the small fan-out typical of domain
// labels, is faster than map lookup due to cache locality.
type Node struct {
	Children []childEntry
	Blocked  bool
}

// findChild performs binary search on sorted children slice.
func (n *Node) findChild(label string) (*Node, bool) {
	lo, hi := 0, len(n.Children)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1) // avoid overflow
		switch {
		case n.Children[mid].Label < label:
			lo = mid + 1
		case n.Children[mid].Label > label:
			hi = mid - 1
		default:
			return n.Children[mid].Node, true
		}
	}
	return nil, false
}

// addChild inserts a child in sorted order via binary search.
// If the label already exists, returns the existing child.
func (n *Node) addChild(label string) *Node {
	lo, hi := 0, len(n.Children)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case n.Children[mid].Label < label:
			lo = mid + 1
		case n.Children[mid].Label > label:
			hi = mid - 1
		default:
			return n.Children[mid].Node
		}
	}
	child := &Node{}
	// Insert at position lo to maintain sorted order.
	n.Children = append(n.Children, childEntry{})
	copy(n.Children[lo+1:], n.Children[lo:])
	n.Children[lo] = childEntry{Label: label, Node: child}
	return child
}

// Trie is an optimized prefix-tree for domains.
// It stores domains in reverse-label order (e.g., com -> example -> ads).
// It is lock-free for readers once built.
type Trie struct {
	root *Node
	size int
}

// NewTrie creates a new, empty Domain filter.
func NewTrie() *Trie {
	return &Trie{
		root: &Node{},
		size: 0,
	}
}

// normalizeDomain lowercases, trims, and converts to ASCII (Punycode).
// This ensures Unicode and Punycode forms of the same domain always match.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return domain
	}
	return ascii
}

// Add inserts a domain into the filter.
// e.g., Add("ads.example.com")
// Domains that are public suffixes (bare TLDs like "com", "vn", or multi-label
// registries like "co.uk", "com.vn") are rejected as a safety guard to prevent
// catastrophic over-blocking.
func (t *Trie) Add(domain string) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return
	}

	// Clean the domain for the publicsuffix check (it dislikes trailing/double dots)
	checkDomain := strings.TrimRight(domain, ".")
	for strings.Contains(checkDomain, "..") {
		checkDomain = strings.ReplaceAll(checkDomain, "..", ".")
	}

	// Safety guard: reject domains that ARE a public suffix (TLD or
	// multi-label registries like "co.uk", "com.vn", "edu.vn").
	// publicsuffix.EffectiveTLDPlusOne returns error when the input
	// is itself a suffix, which is exactly what we want to reject.
	if _, err := publicsuffix.EffectiveTLDPlusOne(checkDomain); err != nil {
		return
	}

	curr := t.root

	// Insert from TLD down to the specific subdomain.
	// Zero-allocation: scan the string in reverse looking for '.' separators.
	end := len(domain)
	for end > 0 {
		start := strings.LastIndexByte(domain[:end], '.')
		label := domain[start+1 : end]
		end = start // will be -1 when no more dots → loop terminates
		if label == "" {
			continue // skip empty labels e.g. from trailing dots
		}
		curr = curr.addChild(label)
	}

	if !curr.Blocked {
		curr.Blocked = true
		t.size++
	}
}

// Match checks if the domain or any of its parent root domains are blocked.
// e.g., if "example.com" is blocked, Match("sub.example.com") returns true.
// Zero-allocation: scans the domain string in reverse without splitting.
func (t *Trie) Match(domain string) bool {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}

	curr := t.root

	end := len(domain)
	for end > 0 {
		start := strings.LastIndexByte(domain[:end], '.')
		label := domain[start+1 : end]
		end = start
		if label == "" {
			continue
		}
		child, exists := curr.findChild(label)
		if !exists {
			return false
		}
		if child.Blocked {
			return true
		}
		curr = child
	}

	return false
}

// Clear clears the trie. Not thread-safe for active readers.
func (t *Trie) Clear() {
	t.root = &Node{}
	t.size = 0
}

// Count returns the number of blocked domains.
func (t *Trie) Count() int {
	return t.size
}

// WriteTo writes all domains in the filter to the provided writer, sorted alphabetically.
func (t *Trie) WriteTo(w io.Writer) (int64, error) {
	var total int64
	var err error

	var walk func(node *Node, path []string)
	walk = func(node *Node, path []string) {
		if err != nil {
			return
		}
		if node.Blocked {
			// reconstruct domain (path is from TLD down)
			domainParts := make([]string, len(path))
			for i, p := range path {
				domainParts[len(path)-1-i] = p
			}
			domain := strings.Join(domainParts, ".")
			var n int
			n, err = fmt.Fprintln(w, domain)
			total += int64(n)
			if err != nil {
				return
			}
		}

		if len(node.Children) == 0 {
			return
		}

		// Children are already sorted, iterate in order.
		for _, child := range node.Children {
			walk(child.Node, append(path, child.Label))
		}
	}

	walk(t.root, nil)
	return total, err
}
