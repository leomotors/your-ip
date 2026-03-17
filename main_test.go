package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClassifyIP(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "Public"},
		{"1.1.1.1", "Public"},
		{"10.0.0.1", "Private (Class A \u2014 10.0.0.0/8)"},
		{"10.255.255.255", "Private (Class A \u2014 10.0.0.0/8)"},
		{"172.16.0.1", "Private (Class B \u2014 172.16.0.0/12)"},
		{"172.31.255.255", "Private (Class B \u2014 172.16.0.0/12)"},
		{"172.15.0.1", "Public"},
		{"172.32.0.1", "Public"},
		{"192.168.1.1", "Private (Class C \u2014 192.168.0.0/16)"},
		{"192.168.0.0", "Private (Class C \u2014 192.168.0.0/16)"},
		{"100.64.0.1", "CGNAT (100.64.0.0/10)"},
		{"100.127.255.255", "CGNAT (100.64.0.0/10)"},
		{"127.0.0.1", "Loopback"},
		{"::1", "Loopback"},
		{"169.254.1.1", "Link-Local"},
		{"2001:db8::1", "Public"},
		{"fd00::1", "Private (IPv6 ULA)"},
		{"not-an-ip", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := classifyIP(tt.ip)
			if got != tt.want {
				t.Errorf("classifyIP(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIPVersion(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"8.8.8.8", "IPv4"},
		{"192.168.1.1", "IPv4"},
		{"::1", "IPv6"},
		{"2001:db8::1", "IPv6"},
		{"bad", "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := ipVersion(tt.ip)
			if got != tt.want {
				t.Errorf("ipVersion(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestDetectIP_Headers(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		wantIP     string
		wantMethod string
	}{
		{
			name:       "Cloudflare CF-Connecting-IP",
			headers:    map[string]string{"Cf-Connecting-Ip": "203.0.113.50"},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "203.0.113.50",
			wantMethod: "Cloudflare (CF-Connecting-IP)",
		},
		{
			name:       "X-Real-IP",
			headers:    map[string]string{"X-Real-Ip": "198.51.100.10"},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "198.51.100.10",
			wantMethod: "Nginx / Traefik (X-Real-IP)",
		},
		{
			name:       "X-Forwarded-For first IP",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.1, 10.0.0.2"},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "203.0.113.1",
			wantMethod: "Reverse Proxy (X-Forwarded-For)",
		},
		{
			name:       "Forwarded header RFC 7239",
			headers:    map[string]string{"Forwarded": "for=192.0.2.60;proto=http;by=203.0.113.43"},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "192.0.2.60",
			wantMethod: "RFC 7239 (Forwarded)",
		},
		{
			name:       "Forwarded header IPv6",
			headers:    map[string]string{"Forwarded": "for=\"[2001:db8::1]\""},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "2001:db8::1",
			wantMethod: "RFC 7239 (Forwarded)",
		},
		{
			name:       "Direct connection fallback",
			headers:    map[string]string{},
			remoteAddr: "203.0.113.99:54321",
			wantIP:     "203.0.113.99",
			wantMethod: "Direct Connection (RemoteAddr)",
		},
		{
			name:       "CF-Connecting-IP takes priority over X-Forwarded-For",
			headers:    map[string]string{"Cf-Connecting-Ip": "203.0.113.50", "X-Forwarded-For": "198.51.100.1"},
			remoteAddr: "10.0.0.1:12345",
			wantIP:     "203.0.113.50",
			wantMethod: "Cloudflare (CF-Connecting-IP)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/ip", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			gotIP, gotMethod := detectIP(req)
			if gotIP != tt.wantIP {
				t.Errorf("detectIP() IP = %q, want %q", gotIP, tt.wantIP)
			}
			if gotMethod != tt.wantMethod {
				t.Errorf("detectIP() method = %q, want %q", gotMethod, tt.wantMethod)
			}
		})
	}
}

func TestHandleIP_Response(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/ip", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	rr := httptest.NewRecorder()
	handleIP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	if cc := rr.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control header not set")
	}

	var resp IPResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.IP != "192.168.1.100" {
		t.Errorf("IP = %q, want 192.168.1.100", resp.IP)
	}
	if resp.IPType == "" {
		t.Error("IPType should not be empty")
	}
	if resp.Version == "" {
		t.Error("Version should not be empty")
	}
	if resp.Method == "" {
		t.Error("Method should not be empty")
	}
}
