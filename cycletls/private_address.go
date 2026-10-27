package cycletls

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// privateAddressPrefixes matches isPrivateAddress in bugsmash-proxy-server src/request-utils.js.
var privateAddressPrefixes = func() []netip.Prefix {
	cidrs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	}
	prefixes := make([]netip.Prefix, len(cidrs))
	for i, cidr := range cidrs {
		prefixes[i] = netip.MustParsePrefix(cidr)
	}
	return prefixes
}()

// isPrivateAddress reports whether ip is an internal address. IPv4-mapped IPv6 is checked as IPv4.
func isPrivateAddress(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, prefix := range privateAddressPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// checkDialAddress returns an error when address ("ip:port") is an internal address.
func checkDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("blockPrivateAddresses: cannot parse dial address %q: %w", address, err)
	}
	if isPrivateAddress(ip) {
		return fmt.Errorf("blockPrivateAddresses: connection to private address %s is not allowed", ip)
	}
	return nil
}

// rejectPrivateAddressControl is a net.Dialer Control function. It runs after DNS resolution,
// on the exact address the socket connects to, so a DNS rebinding answer cannot pass it.
func rejectPrivateAddressControl(_, address string, _ syscall.RawConn) error {
	return checkDialAddress(address)
}
