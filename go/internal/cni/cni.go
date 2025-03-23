package cni

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/HomayoonAlimohammadi/fancni/pkg/cni"
	pkgcni "github.com/HomayoonAlimohammadi/fancni/pkg/cni"
	"github.com/HomayoonAlimohammadi/fancni/pkg/command"
	"github.com/HomayoonAlimohammadi/fancni/pkg/fan"
	pkgipam "github.com/HomayoonAlimohammadi/fancni/pkg/ipam"
	pkgnet "github.com/HomayoonAlimohammadi/fancni/pkg/net"
)

const (
	defaultBridgeName        string = "cni0"
	defaultCNIVersion        string = "0.3.1"
	defaultSupportedVersions string = "[ \"0.3.0\", \"0.3.1\", \"0.4.0\" ]"
)

// plugin represents the CNI plugin.
type plugin struct {
	cniVersion           string
	cniSupportedVersions string

	ifName      string
	netNS       string
	containerID string

	config cni.NetConfig
	ipam   pkgipam.IPAM
	hostIP net.IP
}

func NewPlugin(netConfig pkgcni.NetConfig, ipam pkgipam.IPAM, hostIP net.IP) *plugin {
	p := &plugin{
		cniVersion:           defaultCNIVersion,
		cniSupportedVersions: defaultSupportedVersions,

		ifName:      os.Getenv(pkgcni.EnvIFName),
		netNS:       os.Getenv(pkgcni.EnvNetNS),
		containerID: os.Getenv(pkgcni.EnvContainerID),

		config: netConfig,
		ipam:   ipam,
		hostIP: hostIP,
	}

	return p
}

// HandleAdd implements the ADD command.
func (c *plugin) HandleAdd() error {
	underlayNetwork, err := fan.GetUnderlayNetwork(c.hostIP)
	if err != nil {
		return fmt.Errorf("failed to get underlay network: %w", err)
	}

	fanBridgeName, err := fan.GetBridgeName(c.config.OverlayNetwork)
	if err != nil {
		return fmt.Errorf("failed to get fan bridge name: %w", err)
	}

	fanGatewayIP, err := fan.GetGatewayIP(c.config.OverlayNetwork, c.hostIP)
	if err != nil {
		return fmt.Errorf("failed to get fan gateway IP: %w", err)
	}

	if err := fan.Ensure(fanBridgeName, c.config.OverlayNetwork, underlayNetwork); err != nil {
		return fmt.Errorf("failed to ensure fan device: %w", err)
	}

	podIP, err := c.ipam.AllocateIP(c.containerID)
	if err != nil {
		return fmt.Errorf("IP allocation failed: %w", err)
	}

	interim := strings.Split(podIP.String(), ".")
	devNum := interim[len(interim)-1]

	hostIfname := pkgnet.HostPeerName(devNum)
	podIfname := pkgnet.ContainerPeerName(devNum)

	if err := command.Run("ip", "link", "add", hostIfname, "type", "veth", "peer", "name", podIfname); err != nil {
		return fmt.Errorf("failed to add veth pair: %w", err)
	}

	if err := command.Run("ip", "link", "set", hostIfname, "up"); err != nil {
		return fmt.Errorf("failed to set %s up: %w", hostIfname, err)
	}

	contNetns := filepath.Base(c.netNS)

	if err := command.Run("ip", "link", "set", hostIfname, "master", fanBridgeName); err != nil {
		return fmt.Errorf("failed to set %s master to %s: %w", hostIfname, fanBridgeName, err)
	}

	if err := command.Run("ip", "link", "set", podIfname, "netns", contNetns); err != nil {
		return fmt.Errorf("failed to set %s into netns %s: %w", podIfname, contNetns, err)
	}

	if err := command.Run("ip", "-n", contNetns, "link", "set", podIfname, "name", c.ifName); err != nil {
		return fmt.Errorf("failed to rename interface in netns: %w", err)
	}

	if err := command.Run("ip", "-n", contNetns, "link", "set", c.ifName, "up"); err != nil {
		return fmt.Errorf("failed to set interface %s up in netns: %w", c.ifName, err)
	}

	if err := command.Run("ip", "-n", contNetns, "addr", "add", fmt.Sprintf("%s/24", podIP.String()), "dev", c.ifName); err != nil {
		return fmt.Errorf("failed to add address to interface in netns: %w", err)
	}

	if err := command.Run("ip", "-n", contNetns, "route", "add", "default", "via", fanGatewayIP.String()); err != nil {
		return fmt.Errorf("failed to add default route to %s in netns: %w", fanGatewayIP.String(), err)
	}

	mac, err := pkgnet.GetInterfaceMAC(contNetns, c.ifName)
	if err != nil {
		return fmt.Errorf("failed to get MAC address: %v", err)
	}

	result := cni.Result{
		CNIVersion: c.cniVersion,
	}
	result.Interfaces = []cni.Interface{
		{
			Name:    c.ifName,
			MAC:     mac,
			Sandbox: c.netNS,
		},
	}
	result.IPs = []cni.IP{
		{
			// NOTE(Hue): Only IPv4 is supported for now.
			Version:   "4",
			Address:   fmt.Sprintf("%s/24", podIP.String()),
			Gateway:   fanGatewayIP.String(),
			Interface: 0,
		},
	}

	outputBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	output := string(outputBytes)
	log.Printf("OUTPUT: %s", output)
	fmt.Fprintln(os.Stdout, output)

	return nil
}

// HandleDel implements the DEL command.
func (c *plugin) HandleDel() error {
	ip, found, err := c.ipam.Lookup(c.containerID)
	if err != nil {
		return fmt.Errorf("failed to lookup IP: %w", err)
	}

	if found {
		log.Printf("Found IP %s for container %s", ip.String(), c.containerID)
	} else {
		log.Printf("No IP found for container %s", c.containerID)
		return nil
	}

	if _, found, err = c.ipam.Free(ip); err != nil {
		return fmt.Errorf("failed to free IP: %w", err)
	}

	if found {
		log.Printf("Freed IP %s", ip.String())
	} else {
		log.Printf("IP %s not found in allocation file", ip.String())
	}

	// NOTE(Hue): The host veth peer number is the last octet of the IP address.
	interm := strings.Split(ip.String(), ".")
	devNum := interm[len(interm)-1]

	hostIfname := pkgnet.HostPeerName(devNum)
	if err := command.Run("ip", "link", "del", hostIfname); err != nil {
		if strings.Contains(err.Error(), "Cannot find device") {
			log.Printf("Interface %s not found, ignoring error", hostIfname)
		} else {
			return fmt.Errorf("failed to delete interface %s: %w", hostIfname, err)
		}
	} else {
		log.Printf("Deleted %s", hostIfname)
	}

	return nil
}

// HandleGet implements the GET command.
func (c *plugin) HandleGet() error {
	// Implement the GET command if needed.
	// Currently, it just returns nil.
	return nil
}

// HandleVersion implements the VERSION command.
func (c *plugin) HandleVersion() error {
	versionJSON := `{
  "cniVersion": %s, 
  "supportedVersions": %s
}`
	fmt.Printf(versionJSON, c.cniVersion, c.cniSupportedVersions)
	return nil
}
