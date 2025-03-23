package ip

import (
	"fmt"
	"net"
	"strings"
)

// ReplaceLastOctet replaces the last octet of an IP address string with a given integer.
// It assumes the IP address is in the format "x.x.x.x".
// We don't check this assumption for efficienty and it's on the caller to ensure the format.
func ReplaceLastOctet(ip net.IP, n int) (net.IP, error) {
	parts := strings.Split(ip.String(), ".")
	parts[3] = fmt.Sprint(n)
	parsed := net.ParseIP(strings.Join(parts, "."))
	if parsed == nil {
		return nil, fmt.Errorf("failed to parse IP: %s", strings.Join(parts, "."))
	}
	return parsed, nil
}

// GetGatewayIP calculates the gateway IP address by adding 1 to the base IP.
func GetGatewayIP(baseIP net.IP) (net.IP, error) {
	if baseIP.To4() == nil {
		return nil, fmt.Errorf("base IP is not IPv4")
	}

	gwIP, err := ReplaceLastOctet(baseIP, 1)
	if err != nil {
		return nil, fmt.Errorf("failed to replace last octet of IP %q: %w", baseIP, err)
	}

	return gwIP, nil
}

// GetHostIP retrieves the host IP address by connecting to a public DNS server.
func GetHostIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}
