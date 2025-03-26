package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	internalcni "github.com/canonical/fancni/internal/cni"
	"github.com/canonical/fancni/internal/config"
	internalipam "github.com/canonical/fancni/internal/ipam"
	pkgcni "github.com/canonical/fancni/pkg/cni"
	"github.com/canonical/fancni/pkg/fan"
	"github.com/canonical/fancni/pkg/net/ip"
)

const (
	ipamAllocFile string = "/tmp/ipam.json"
	ipamLockFile  string = "/tmp/ipam.lock"
	logFile       string = "/var/log/cni.log"
)

func main() {
	logFile, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetPrefix(fmt.Sprintf("[PID: %d]", os.Getpid()))

	netConfig, err := config.ReadNetConfig(os.Stdin)
	if err != nil {
		log.Fatalf("failed to read net config: %v\n", err)
	}

	logStuff(netConfig)
	ensureBinaries()

	hostIP, err := ip.GetHostIP()
	if err != nil {
		log.Fatalf("failed to get host IP: %v\n", err)
	}

	podCIDR, err := fan.GetSubnet(netConfig.OverlayNetwork, hostIP)
	if err != nil {
		log.Fatalf("failed to get fan subnet: %v\n", err)
	}

	ipam := internalipam.NewFileIPAM(ipamLockFile, ipamAllocFile, podCIDR)
	plugin := internalcni.NewPlugin(netConfig, ipam, hostIP)

	cmd := os.Getenv(pkgcni.EnvCommand)
	switch cmd {
	case pkgcni.CommandAdd:
		if err := plugin.HandleAdd(); err != nil {
			log.Fatalf("failed to handle add: %v\n", err)
		}
	case pkgcni.CommandDel:
		if err := plugin.HandleDel(); err != nil {
			log.Fatalf("failed to handle del: %v\n", err)
		}
	case pkgcni.CommandGet:
		if err := plugin.HandleGet(); err != nil {
			log.Fatalf("failed to handle get: %v\n", err)
		}
	case pkgcni.CommandVersion:
		if err := plugin.HandleVersion(); err != nil {
			log.Fatalf("failed to handle version: %v\n", err)
		}
	default:
		log.Fatalf("unknown CNI command: %s\n", cmd)
	}
}

// logStuff logs the environment variables and the net config.
// (or really anything else that might be necessary for debugging :D)
func logStuff(netConfig pkgcni.NetConfig) {
	log.Printf("PATH: %s", os.Getenv("PATH"))
	envVars := []string{pkgcni.EnvCommand, pkgcni.EnvIFName, pkgcni.EnvNetNS, pkgcni.EnvContainerID}
	for _, env := range envVars {
		log.Printf("%s: %s", env, os.Getenv(env))
	}
	log.Printf("STDIN: %+v", netConfig)
}

// ensureBinaries checks if the required binaries are installed and available in the PATH.
func ensureBinaries() {
	binaries := []string{"ip", "iptables", "fanctl"}
	for _, binary := range binaries {
		if _, err := exec.LookPath(binary); err != nil {
			log.Fatalf("required binary %s not found in PATH: %v\n", binary, err)
		}
	}
}
