package ipam

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	pkgipam "github.com/canonical/fancni/pkg/ipam"
	"github.com/canonical/fancni/pkg/net/ip"
)

// FileIPAM implements the IPAM interface using a file as the backend.
type FileIPAM struct {
	lockFile       string
	lockFilePerm   os.FileMode
	lockMaxRetries int
	lockRetryDelay time.Duration
	allocFile      string
	allocFilePerm  os.FileMode
	podCIDR        string
}

var _ pkgipam.IPAM = &FileIPAM{}

// NewFileIPAM creates a new inFileIPAM instance with the specified lock file and allocation file.
func NewFileIPAM(lockFile, allocFile string, podCIDR string) *FileIPAM {
	return &FileIPAM{
		lockFile:       lockFile,
		lockFilePerm:   0644,
		lockMaxRetries: 100,
		lockRetryDelay: 100 * time.Millisecond,
		allocFile:      allocFile,
		allocFilePerm:  0644,
		podCIDR:        podCIDR,
	}
}

// Lock acquires a lock on the file descriptor.
func (i *FileIPAM) Lock(fd uintptr) error {
	var attempt int
	for {
		err := syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		// Check if error is EWOULDBLOCK (lock is held by someone else)
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("failed to acquire lock: %w", err)
		}

		attempt++
		if attempt >= i.lockMaxRetries {
			return fmt.Errorf("failed to acquire lock after %d attempts: %w", attempt, err)
		}
		time.Sleep(i.lockRetryDelay)
	}
}

// Unlock releases the lock on the file descriptor.
func (i *FileIPAM) Unlock(fd uintptr) error {
	if err := syscall.Flock(int(fd), syscall.LOCK_UN); err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	return nil
}

// AllocateIP allocates an IP address for a container.
func (i *FileIPAM) AllocateIP(containerID string) (net.IP, error) {
	lockFile, err := os.OpenFile(i.lockFile, os.O_CREATE|os.O_RDWR, i.lockFilePerm)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := i.Lock(lockFile.Fd()); err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if err := i.Unlock(lockFile.Fd()); err != nil {
			log.Printf("failed to release lock: %v", err)
		}
	}()

	baseIP, ipNet, err := net.ParseCIDR(i.podCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse podCIDR: %v", err)
	}

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read allocation file: %w", err)
		}
	}

	contIDToIP := make(map[string]string)

	if len(b) > 0 {
		if err := json.Unmarshal(b, &contIDToIP); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allocation file: %w", err)
		}
	}

	allocatedIPs := make(map[string]struct{}, len(contIDToIP))
	for _, ip := range contIDToIP {
		allocatedIPs[ip] = struct{}{}
	}

	for last := 2; last < 255; last++ {
		candidIP, err := ip.ReplaceLastOctet(baseIP, last)
		if err != nil {
			return nil, fmt.Errorf("failed to replace last octet of IP %q: %w", baseIP, err)
		}

		if _, exists := allocatedIPs[candidIP.String()]; !exists {
			// Found an available IP
			contIDToIP[containerID] = candidIP.String()
			break
		}
	}

	ipStr := contIDToIP[containerID]
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("failed to parse allocated IP: %w", err)
	}

	if !ipNet.Contains(ip) {
		// shouldn't happen?
		return nil, fmt.Errorf("allocated IP %s is out of the podCIDR range %s", ipStr, ipNet.String())
	}

	ipMapBytes, err := json.MarshalIndent(contIDToIP, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal allocation map: %w", err)
	}

	// Write the new allocation back.
	// marshal the map to JSON and write to file
	if err := os.WriteFile(i.allocFile, ipMapBytes, i.allocFilePerm); err != nil {
		return nil, fmt.Errorf("failed to write allocation file: %w", err)
	}

	log.Printf("Allocated IP %s for container %s", ip.String(), containerID)

	return ip, nil
}

// Lookup checks if an IP address is allocated to a container.
// It returns the IP address and a boolean indicating if it was found, and an error in any.
func (i *FileIPAM) Lookup(containerID string) (net.IP, bool, error) {
	lockFile, err := os.OpenFile(i.lockFile, os.O_CREATE|os.O_RDWR, i.lockFilePerm)
	if err != nil {
		return nil, false, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := i.Lock(lockFile.Fd()); err != nil {
		return nil, false, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if err := i.Unlock(lockFile.Fd()); err != nil {
			log.Printf("failed to release lock: %v", err)
		}
	}()

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read allocation file: %w", err)
	}

	contIDToIP := make(map[string]string)
	if err := json.Unmarshal(b, &contIDToIP); err != nil {
		return nil, false, fmt.Errorf("failed to unmarshal allocation file: %w", err)
	}

	ipStr, exists := contIDToIP[containerID]
	if !exists {
		return nil, false, nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, false, fmt.Errorf("failed to parse allocated IP: %w", err)
	}

	return ip, true, nil
}

// Free frees the allocated IP address for a container.
// It returns the container ID associated with the IP address if there is any.
func (i *FileIPAM) Free(ip net.IP) (string, bool, error) {
	lockFile, err := os.OpenFile(i.lockFile, os.O_CREATE|os.O_RDWR, i.lockFilePerm)
	if err != nil {
		return "", false, fmt.Errorf("failed to open lock file: %w", err)
	}
	defer lockFile.Close()

	if err := i.Lock(lockFile.Fd()); err != nil {
		return "", false, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if err := i.Unlock(lockFile.Fd()); err != nil {
			log.Printf("failed to release lock: %v", err)
		}
	}()

	b, err := os.ReadFile(i.allocFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("failed to read allocation file: %w", err)
	}

	contIDToIP := make(map[string]string)
	if err := json.Unmarshal(b, &contIDToIP); err != nil {
		return "", false, fmt.Errorf("failed to unmarshal allocation file: %w", err)
	}

	// Find the container ID associated with the IP address.
	var containerID string
	for id, ipStr := range contIDToIP {
		if ipStr == ip.String() {
			containerID = id
			break
		}
	}

	if containerID == "" {
		return "", false, nil
	}

	delete(contIDToIP, containerID)

	ipMapBytes, err := json.MarshalIndent(contIDToIP, "", "  ")
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal allocation map: %w", err)
	}

	// Write the updated allocation back.
	if err := os.WriteFile(i.allocFile, ipMapBytes, i.allocFilePerm); err != nil {
		return "", false, fmt.Errorf("failed to write allocation file: %w", err)
	}

	return containerID, true, nil
}
