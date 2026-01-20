package app

import (
	"net"
	"os"
	"runtime"
)

// SystemInfo holds basic information about the host system.
type SystemInfo struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	IP       string `json:"ip"`
}

// GetSystemInfo returns basic host details to display on the dashboard.
func (a *App) GetSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()

	// Get first non-loopback IP
	ip := "Unknown"
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip = ipnet.IP.String()
					break
				}
			}
		}
	}

	return SystemInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		IP:       ip,
	}
}
