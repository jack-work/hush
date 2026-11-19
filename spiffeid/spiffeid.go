package spiffeid

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const maxLen = 2048

var (
	trustDomain = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	segment     = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

type ID struct {
	trustDomain string
	path        string
}

func ValidTrustDomain(td string) error {
	if !trustDomain.MatchString(td) {
		return fmt.Errorf("trust domain %q: want lowercase letters, digits and inner hyphens, at most 63", td)
	}
	return nil
}

func New(td string, segments ...string) (ID, error) {
	if err := ValidTrustDomain(td); err != nil {
		return ID{}, err
	}
	if len(segments) == 0 {
		return ID{}, errors.New("spiffe id: a workload id needs a path")
	}
	for _, s := range segments {
		if err := validSegment(s); err != nil {
			return ID{}, err
		}
	}
	id := ID{trustDomain: td, path: "/" + strings.Join(segments, "/")}
	if len(id.String()) > maxLen {
		return ID{}, fmt.Errorf("spiffe id: longer than %d bytes", maxLen)
	}
	return id, nil
}

func Parse(s string) (ID, error) {
	if len(s) > maxLen {
		return ID{}, fmt.Errorf("spiffe id: longer than %d bytes", maxLen)
	}
	rest, ok := strings.CutPrefix(s, "spiffe://")
	if !ok {
		return ID{}, fmt.Errorf("spiffe id %q: want the spiffe scheme", s)
	}
	if strings.ContainsAny(rest, "?#@%") {
		return ID{}, fmt.Errorf("spiffe id %q: no query, fragment, user info or escapes", s)
	}
	td, path, _ := strings.Cut(rest, "/")
	if strings.Contains(td, ":") {
		return ID{}, fmt.Errorf("spiffe id %q: no port", s)
	}
	if path == "" {
		return ID{}, fmt.Errorf("spiffe id %q: a workload id needs a path", s)
	}
	return New(td, strings.Split(path, "/")...)
}

func FromURL(u *url.URL) (ID, error) {
	if u == nil {
		return ID{}, errors.New("spiffe id: none")
	}
	return Parse(u.String())
}

func validSegment(s string) error {
	if s == "" || s == "." || s == ".." {
		return fmt.Errorf("spiffe id: path segment %q is empty or a dot segment", s)
	}
	if !segment.MatchString(s) {
		return fmt.Errorf("spiffe id: path segment %q: want letters, digits, '.', '-' and '_'", s)
	}
	return nil
}

func (id ID) TrustDomain() string { return id.trustDomain }
func (id ID) Path() string        { return id.path }
func (id ID) IsZero() bool        { return id.trustDomain == "" }

func (id ID) String() string {
	if id.IsZero() {
		return ""
	}
	return "spiffe://" + id.trustDomain + id.path
}

func (id ID) URL() *url.URL {
	return &url.URL{Scheme: "spiffe", Host: id.trustDomain, Path: id.path}
}

func (id ID) Segments() []string {
	return strings.Split(strings.TrimPrefix(id.path, "/"), "/")
}

func Node(td, node string) (ID, error) {
	return New(td, "node", node)
}

func (id ID) Node() (string, bool) {
	s := id.Segments()
	if len(s) < 2 || s[0] != "node" {
		return "", false
	}
	return s[1], true
}

func (id ID) IsNode() bool {
	_, ok := id.Node()
	return ok && len(id.Segments()) == 2
}

func (id ID) Under(node string) bool {
	n, ok := id.Node()
	return ok && n == node
}
