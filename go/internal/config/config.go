package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net"

	pkgcni "github.com/HomayoonAlimohammadi/fancni/pkg/cni"
)

func ReadNetConfig(r io.Reader) (pkgcni.NetConfig, error) {
	configBytes, err := io.ReadAll(r)
	if err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to read config from stdin: %w", err)
	}

	var netConfig pkgcni.NetConfig
	if err := json.Unmarshal(configBytes, &netConfig); err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to parse config JSON: %w", err)
	}

	if netConfig.OverlayNetwork == "" {
		return pkgcni.NetConfig{}, fmt.Errorf("overlay network not specified in config")
	}

	baseIP, _, err := net.ParseCIDR(netConfig.OverlayNetwork)
	if err != nil {
		return pkgcni.NetConfig{}, fmt.Errorf("failed to parse overlay network %q: %w", netConfig.OverlayNetwork, err)
	}
	if baseIP.To4() == nil {
		return pkgcni.NetConfig{}, fmt.Errorf("overlay network %q is not IPv4. Only IPv4 is supported", netConfig.OverlayNetwork)
	}

	return netConfig, nil
}
