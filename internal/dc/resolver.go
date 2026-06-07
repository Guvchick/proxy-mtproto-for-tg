// Package dc maps Telegram DC IDs to upstream TCP addresses.
package dc

import (
	"fmt"
	"net"
)

// Entry holds both address families for one DC.
type Entry struct {
	IPv4 string
	IPv6 string
}

// Known Telegram DC addresses (port 443).
var known = map[int]Entry{
	1: {"149.154.175.50:443", "[2001:b28:f23d:f001::a]:443"},
	2: {"149.154.167.51:443", "[2001:67c:4e8:f002::a]:443"},
	3: {"149.154.175.100:443", "[2001:b28:f23d:f003::a]:443"},
	4: {"149.154.167.91:443", "[2001:67c:4e8:f004::a]:443"},
	5: {"91.108.56.130:443", "[2001:b28:f23e:f005::a]:443"},
}

// AddrFamily controls which address family the resolver picks.
type AddrFamily int

const (
	IPv4       AddrFamily = iota
	IPv6                  // fail if no IPv6 address
	PreferIPv6            // try IPv6, fall back to IPv4
)

// Resolve returns the upstream address for the given DC and address family.
func Resolve(dcID int, family AddrFamily) (string, error) {
	entry, ok := known[dcID]
	if !ok {
		return "", fmt.Errorf("unknown DC ID: %d", dcID)
	}
	switch family {
	case IPv6:
		if entry.IPv6 == "" {
			return "", fmt.Errorf("no IPv6 address for DC %d", dcID)
		}
		return entry.IPv6, nil
	case PreferIPv6:
		if entry.IPv6 != "" {
			return entry.IPv6, nil
		}
		return entry.IPv4, nil
	default:
		return entry.IPv4, nil
	}
}

// ParseFamily converts a string config value to AddrFamily.
func ParseFamily(s string) (AddrFamily, error) {
	switch s {
	case "ipv4", "":
		return IPv4, nil
	case "ipv6":
		return IPv6, nil
	case "prefer-ipv6":
		return PreferIPv6, nil
	default:
		return 0, fmt.Errorf("unknown addr_family: %q", s)
	}
}

// Dial opens a TCP connection to the given DC.
func Dial(dcID int, family AddrFamily) (net.Conn, error) {
	addr, err := Resolve(dcID, family)
	if err != nil {
		return nil, err
	}
	return net.Dial("tcp", addr)
}
