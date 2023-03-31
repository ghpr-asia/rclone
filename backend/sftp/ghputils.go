//go:build !plan9
// +build !plan9

package sftp

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var reProxyJump = regexp.MustCompile(
	// optional username, note that outside group
	`(?:(?P<username>[^\:]+)@)?(?P<hostport>[^\@]+)`,
)

// NetAddr is network address that includes network, optional path and
// host port
type NetAddr struct {
	// Addr is the host:port address, like "localhost:22"
	Addr string `json:"addr"`
	// AddrNetwork is the type of a network socket, like "tcp" or "unix"
	AddrNetwork string `json:"network,omitempty"`
	// Path is a socket file path, like '/var/path/to/socket' in "unix:///var/path/to/socket"
	Path string `json:"path,omitempty"`
}

// JumpHost is a target jump host
type JumpHost struct {
	// Username to login as
	Username string
	// Addr is a target addr
	Addr NetAddr
}

// ParseAddr takes strings like "tcp://host:port/path" and returns
// *NetAddr or an error
func ParseAddr(a string) (*NetAddr, error) {
	if a == "" {
		return nil, fmt.Errorf("missing parameter address")
	}
	if !strings.Contains(a, "://") {
		a = "tcp://" + a
	}
	u, err := url.Parse(a)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %w", a, err)
	}
	switch u.Scheme {
	case "tcp":
		return &NetAddr{Addr: u.Host, AddrNetwork: u.Scheme, Path: u.Path}, nil
	case "unix":
		return &NetAddr{Addr: u.Path, AddrNetwork: u.Scheme}, nil
	case "http", "https":
		return &NetAddr{Addr: u.Host, AddrNetwork: u.Scheme, Path: u.Path}, nil
	default:
		return nil, fmt.Errorf("'%v': unsupported scheme: '%v'", a, u.Scheme)
	}
}

// ParseProxyJump parses strings like user@host:port,bob@host:port
func ParseProxyJump(in string) ([]JumpHost, error) {
	if in == "" {
		return []JumpHost{}, nil
	}
	parts := strings.Split(in, ",")
	out := make([]JumpHost, 0, len(parts))
	for _, part := range parts {
		match := reProxyJump.FindStringSubmatch(strings.TrimSpace(part))
		if len(match) == 0 {
			return nil, fmt.Errorf("could not parse %q, expected format user@host:port,user@host:port", in)
		}
		addr, err := ParseAddr(match[2])
		if err != nil {
			return nil, fmt.Errorf("unexpected error while parsing jumphost address: %w", err)
		}
		out = append(out, JumpHost{Username: match[1], Addr: *addr})
	}
	return out, nil
}
