package netutil

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

var transportBypassIPv4WildcardPattern = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){0,2})\.\*$`)

type TransportBypassMatcher struct {
	exactHosts     map[string]struct{}
	exactIPs       []net.IP
	domainSuffixes []string
	ipv4Prefixes   []string
	cidrs          []*net.IPNet
}

func ParseTransportBypassEnv(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func NormalizeTransportBypassList(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	normalized := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		rule, err := normalizeTransportBypassRule(item)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[rule]; ok {
			continue
		}
		seen[rule] = struct{}{}
		normalized = append(normalized, rule)
	}
	return normalized, nil
}

func CompileTransportBypassMatcher(rules []string) (*TransportBypassMatcher, error) {
	normalized, err := NormalizeTransportBypassList(rules)
	if err != nil {
		return nil, err
	}
	matcher := &TransportBypassMatcher{exactHosts: make(map[string]struct{})}
	for _, rule := range normalized {
		switch {
		case strings.HasPrefix(rule, "."):
			matcher.domainSuffixes = append(matcher.domainSuffixes, strings.TrimPrefix(rule, "."))
		case strings.HasSuffix(rule, ".*"):
			matcher.ipv4Prefixes = append(matcher.ipv4Prefixes, strings.TrimSuffix(rule, "*"))
		case strings.Contains(rule, "/"):
			_, network, parseErr := net.ParseCIDR(rule)
			if parseErr != nil {
				return nil, parseErr
			}
			matcher.cidrs = append(matcher.cidrs, network)
		default:
			if ip := net.ParseIP(rule); ip != nil {
				matcher.exactIPs = append(matcher.exactIPs, ip)
				continue
			}
			matcher.exactHosts[rule] = struct{}{}
		}
	}
	return matcher, nil
}

func (m *TransportBypassMatcher) MatchHost(host string) bool {
	if m == nil {
		return false
	}
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return false
	}
	trimmed = strings.Trim(trimmed, "[]")
	lowerHost := strings.ToLower(trimmed)
	if _, ok := m.exactHosts[lowerHost]; ok {
		return true
	}
	for _, suffix := range m.domainSuffixes {
		if lowerHost == suffix || strings.HasSuffix(lowerHost, "."+suffix) {
			return true
		}
	}
	for _, prefix := range m.ipv4Prefixes {
		if strings.HasPrefix(lowerHost, prefix) {
			return true
		}
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return false
	}
	for _, exactIP := range m.exactIPs {
		if exactIP.Equal(ip) {
			return true
		}
	}
	for _, network := range m.cidrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeTransportBypassRule(raw string) (string, error) {
	rule := strings.ToLower(strings.TrimSpace(raw))
	if rule == "" {
		return "", fmt.Errorf("empty bypass rule")
	}
	if strings.Contains(rule, "[") || strings.Contains(rule, "]") {
		return "", fmt.Errorf("invalid bypass rule %q: brackets are not allowed", raw)
	}
	if strings.Contains(rule, "/") {
		if _, _, err := net.ParseCIDR(rule); err != nil {
			return "", fmt.Errorf("invalid bypass rule %q: invalid CIDR: %w", raw, err)
		}
		return rule, nil
	}
	if ip := net.ParseIP(rule); ip != nil {
		return ip.String(), nil
	}
	if strings.Contains(rule, "*") {
		match := transportBypassIPv4WildcardPattern.FindStringSubmatch(rule)
		if match == nil {
			return "", fmt.Errorf("invalid bypass rule %q: wildcard only supports IPv4 dotted prefixes ending with .*", raw)
		}
		segments := strings.Split(match[1], ".")
		for _, segment := range segments {
			if segment == "" {
				return "", fmt.Errorf("invalid bypass rule %q: empty IPv4 segment", raw)
			}
			value := 0
			for _, r := range segment {
				if r < '0' || r > '9' {
					return "", fmt.Errorf("invalid bypass rule %q: invalid IPv4 segment %q", raw, segment)
				}
				value = value*10 + int(r-'0')
			}
			if value > 255 {
				return "", fmt.Errorf("invalid bypass rule %q: invalid IPv4 segment %q", raw, segment)
			}
		}
		return match[1] + ".*", nil
	}
	if strings.HasPrefix(rule, ".") {
		suffix := strings.TrimPrefix(rule, ".")
		if suffix == "" || strings.Contains(suffix, ":") {
			return "", fmt.Errorf("invalid bypass rule %q: invalid domain suffix", raw)
		}
		return "." + suffix, nil
	}
	if strings.Contains(rule, ":") {
		return "", fmt.Errorf("invalid bypass rule %q: ports are not supported", raw)
	}
	return rule, nil
}
