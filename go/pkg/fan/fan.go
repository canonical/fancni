package fan

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/canonical/fancni/pkg/command"
	"github.com/canonical/fancni/pkg/net/ip"
)

// Ensure creates a fan device if it doesn't exist.
func Ensure(bridgeName, overlayNet, underlayNet string) error {
	if bridgeName == "" {
		return fmt.Errorf("bridge name cannot be empty")
	}

	if overlayNet == "" {
		return fmt.Errorf("overlay cannot be empty")
	}

	if underlayNet == "" {
		return fmt.Errorf("host IP cannot be empty")
	}

	if err := command.Run("ip", "link", "show", bridgeName); err != nil && strings.Contains(err.Error(), "does not exist") {
		if err := command.Run("fanctl", "up", "-o", overlayNet, "-u", underlayNet, "dhcp"); err != nil {
			return fmt.Errorf("failed to create fan device: %w", err)
		}

		log.Printf("Created fan device %s with overlay %s and underlay %s", bridgeName, overlayNet, underlayNet)
	}

	return nil
}

// GetGatewayIP retrieves the gateway IP address for the given overlay network with respect to the host IP address.
func GetGatewayIP(overlayNetwork string, hostIP net.IP) (net.IP, error) {
	subnet, err := GetSubnet(overlayNetwork, hostIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get subnet: %w", err)
	}

	baseIP, _, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnet %q: %w", subnet, err)
	}

	if baseIP.To4() == nil {
		return nil, fmt.Errorf("subnet %q is not IPv4. Only IPv4 is supported", subnet)
	}

	gatewayIP, err := ip.GetGatewayIP(baseIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get gateway IP: %w", err)
	}

	return gatewayIP, nil
}

// GetUnderlayNetwork calculates the underlay network based on the host IP address.
func GetUnderlayNetwork(hostIP net.IP) (string, error) {
	if hostIP == nil {
		return "", fmt.Errorf("host IP cannot be empty")
	}

	if hostIP.To4() == nil {
		return "", fmt.Errorf("host IP is not IPv4")
	}

	return fmt.Sprintf("%s/24", hostIP), nil
}

// GetBridgeName generates the bridge name based on the overlay network.
// Example:
//
//	overlayNet: "240.0.0.0/8" -> bridgeName: "fan-240"
//	overlayNet: "10.0.0.0/8" -> bridgeName: "fan-10"
func GetBridgeName(overlayNet string) (string, error) {
	base, _, err := net.ParseCIDR(overlayNet)
	if err != nil {
		return "", fmt.Errorf("failed to parse overlay network: %w", err)
	}

	if base.To4() == nil {
		return "", fmt.Errorf("overlay network is not IPv4")
	}

	parts := strings.Split(base.String(), ".")
	return fanBridgeName(parts[0]), nil
}

// GetSubnet calculates the subnet based on the overlay network and host IP address.
// Example:
//
//	overlay: "240.0.0.0/8", hostIP: "10.72.67.169" -> subnet: "240.67.169.0/24"
func GetSubnet(overlayNet string, hostIP net.IP) (string, error) {
	base, _, err := net.ParseCIDR(overlayNet)
	if err != nil {
		return "", fmt.Errorf("failed to parse overlay network: %w", err)
	}

	if base.To4() == nil {
		return "", fmt.Errorf("overlay network is not IPv4")
	}

	parts := strings.Split(base.String(), ".")

	hostIPParts := strings.Split(hostIP.String(), ".")

	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], hostIPParts[2], hostIPParts[3]), nil
}

// fanBridgeName generates the fan bridge name based on the given suffix.
func fanBridgeName(suffix string) string {
	return fmt.Sprintf("fan-%s", suffix)
}
