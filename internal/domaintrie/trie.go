package domaintrie

import (
	"strings"
	"sync"
)

// Node represents a single label in the domain name.
type Node struct {
	Children map[string]*Node
	IsBlock  bool
}

// Trie is a Radix/Trie tree specialized for domain matching.
// It stores domains in reverse label order (e.g., com -> example -> ads).
type Trie struct {
	mu   sync.RWMutex
	root *Node
}

// NewTrie creates a new, empty Domain Trie.
func NewTrie() *Trie {
	return &Trie{
		root: &Node{
			Children: make(map[string]*Node),
		},
	}
}

// Add inserts a domain into the Trie.
// e.g., Add("ads.example.com")
func (t *Trie) Add(domain string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}
	parts := strings.Split(domain, ".")

	t.mu.Lock()
	defer t.mu.Unlock()

	current := t.root
	// Insert in reverse order: com -> example -> ads
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if current.Children[part] == nil {
			current.Children[part] = &Node{
				Children: make(map[string]*Node),
			}
		}
		current = current.Children[part]
	}
	current.IsBlock = true
}

// Match checks if the domain or any of its parent root domains are blocked.
// e.g., if "example.com" is blocked, Match("sub.example.com") returns true.
func (t *Trie) Match(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	parts := strings.Split(domain, ".")

	t.mu.RLock()
	defer t.mu.RUnlock()

	current := t.root
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		child, ok := current.Children[part]
		if !ok {
			return false // Branch doesn't exist, no match
		}
		if child.IsBlock {
			return true // Matched this exact level (root domain blocked)
		}
		current = child
	}
	return false
}

// Clear removes all domains from the Trie.
func (t *Trie) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.root = &Node{
		Children: make(map[string]*Node),
	}
}

// Count returns the number of blocked domains (leaves).
func (t *Trie) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return countNodes(t.root)
}

func countNodes(n *Node) int {
	if n == nil {
		return 0
	}
	count := 0
	if n.IsBlock {
		count++
	}
	for _, child := range n.Children {
		count += countNodes(child)
	}
	return count
}
