package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

//go:embed static
var staticFiles embed.FS

// IPResponse is the JSON response for the /api/ip endpoint.
type IPResponse struct {
	IP      string `json:"ip"`
	Method  string `json:"method"`
	IPType  string `json:"ipType"`
	Version string `json:"version"`
}

// headerSources defines the priority-ordered list of headers to check for the
// real client IP. Each entry has the header name and a human-readable label
// describing the source (reverse proxy / CDN).
var headerSources = []struct {
	Header string
	Label  string
}{
	{"Cf-Connecting-Ip", "Cloudflare (CF-Connecting-IP)"},
	{"True-Client-Ip", "Cloudflare / Akamai (True-Client-IP)"},
	{"X-Real-Ip", "Nginx / Traefik (X-Real-IP)"},
	{"X-Forwarded-For", "Reverse Proxy (X-Forwarded-For)"},
	{"X-Client-Ip", "Reverse Proxy (X-Client-IP)"},
	{"Forwarded", "RFC 7239 (Forwarded)"},
	{"Fastly-Client-Ip", "Fastly (Fastly-Client-IP)"},
	{"X-Cluster-Client-Ip", "Rackspace / Riverbed (X-Cluster-Client-IP)"},
	{"X-Appengine-User-Ip", "Google App Engine (X-Appengine-User-IP)"},
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ip", handleIP)

	// Serve embedded static files at root
	staticSub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticSub)))

	log.Printf("Your IP server listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func handleIP(w http.ResponseWriter, r *http.Request) {
	// Prevent caching
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/json")

	ip, method := detectIP(r)

	resp := IPResponse{
		IP:      ip,
		Method:  method,
		IPType:  classifyIP(ip),
		Version: ipVersion(ip),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// detectIP walks through known proxy headers in priority order and falls back
// to RemoteAddr if none are present.
func detectIP(r *http.Request) (string, string) {
	for _, src := range headerSources {
		val := r.Header.Get(src.Header)
		if val == "" {
			continue
		}

		var ip string
		if src.Header == "Forwarded" {
			ip = parseForwardedHeader(val)
		} else if src.Header == "X-Forwarded-For" {
			// Take the first (leftmost) IP, which is the original client.
			ip = strings.TrimSpace(strings.SplitN(val, ",", 2)[0])
		} else {
			ip = strings.TrimSpace(val)
		}

		if ip != "" {
			return ip, src.Label
		}
	}

	// Fallback: use RemoteAddr (host:port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return ip, "Direct Connection (RemoteAddr)"
}

// parseForwardedHeader extracts the client IP from RFC 7239 Forwarded header.
// Example: Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43
func parseForwardedHeader(val string) string {
	for _, part := range strings.Split(val, ",") {
		for _, kv := range strings.Split(part, ";") {
			kv = strings.TrimSpace(kv)
			if strings.HasPrefix(strings.ToLower(kv), "for=") {
				addr := kv[4:]
				// Strip quotes and brackets
				addr = strings.Trim(addr, `"`)
				// Handle IPv6: [::1]
				if strings.HasPrefix(addr, "[") {
					if i := strings.Index(addr, "]"); i != -1 {
						return addr[1:i]
					}
				}
				// Strip port if present (1.2.3.4:port)
				if h, _, err := net.SplitHostPort(addr); err == nil {
					return h
				}
				return addr
			}
		}
	}
	return ""
}

// classifyIP determines the type/class of an IP address.
func classifyIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown"
	}

	if ip.IsLoopback() {
		return "Loopback"
	}
	if ip.IsLinkLocalUnicast() {
		return "Link-Local"
	}
	if ip.IsLinkLocalMulticast() {
		return "Link-Local Multicast"
	}
	if ip.IsMulticast() {
		return "Multicast"
	}
	if ip.IsUnspecified() {
		return "Unspecified"
	}

	// Check private ranges
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return "Private (Class A — 10.0.0.0/8)"
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return "Private (Class B — 172.16.0.0/12)"
		case ip4[0] == 192 && ip4[1] == 168:
			return "Private (Class C — 192.168.0.0/16)"
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return "CGNAT (100.64.0.0/10)"
		}
		return "Public"
	}

	// IPv6 private
	if ip.IsPrivate() {
		return "Private (IPv6 ULA)"
	}
	return "Public"
}

// ipVersion returns "IPv4" or "IPv6" based on the address string.
func ipVersion(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown"
	}
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}
