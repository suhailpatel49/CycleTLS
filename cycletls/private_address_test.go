package cycletls

import (
	stdhttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	http "github.com/Danny-Dasilva/fhttp"
)

func TestIsPrivateAddress(t *testing.T) {
	private := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1",
		"ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
	}
	public := []string{"1.1.1.1", "8.8.8.8", "172.32.0.1", "2606:4700:4700::1111", "::ffff:1.1.1.1"}

	for _, address := range private {
		if !isPrivateAddress(netip.MustParseAddr(address)) {
			t.Errorf("%s must be private", address)
		}
	}
	for _, address := range public {
		if isPrivateAddress(netip.MustParseAddr(address)) {
			t.Errorf("%s must be public", address)
		}
	}
	if err := checkDialAddress("[::1]:443"); err == nil {
		t.Error("checkDialAddress must reject [::1]:443")
	}
	if err := checkDialAddress("1.1.1.1:443"); err != nil {
		t.Errorf("checkDialAddress must allow 1.1.1.1:443: %v", err)
	}
}

func TestBlockPrivateAddressesOption(t *testing.T) {
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {}))
	defer server.Close()
	// "localhost" checks that the address is checked after DNS resolution.
	localhostURL := strings.Replace(server.URL, "127.0.0.1", "localhost", 1)

	get := func(browser Browser, url string) error {
		client, err := createNewClient(browser, 5, true, "test")
		if err != nil {
			return err
		}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	open := Browser{JA3: resolverTestJA3, UserAgent: "test"}
	if err := get(open, server.URL); err != nil {
		t.Fatalf("without the option, a local server must be reachable: %v", err)
	}

	blocked := open
	blocked.BlockPrivateAddresses = true
	if generateClientKey(open, 10, false, "") == generateClientKey(blocked, 10, false, "") {
		t.Fatal("blockPrivateAddresses must be part of the client pool key")
	}
	for _, url := range []string{server.URL, localhostURL, "https://localhost:1/"} {
		if err := get(blocked, url); err == nil || !strings.Contains(err.Error(), "blockPrivateAddresses") {
			t.Errorf("%s: want blockPrivateAddresses error, got %v", url, err)
		}
	}

	cloudflare := blocked
	cloudflare.Resolver = "cloudflare"
	if err := get(cloudflare, server.URL); err == nil || !strings.Contains(err.Error(), "blockPrivateAddresses") {
		t.Errorf("cloudflare resolver: want blockPrivateAddresses error, got %v", err)
	}

	http3 := blocked
	http3.ForceHTTP3 = true
	if err := get(http3, "https://localhost:1/"); err == nil || !strings.Contains(err.Error(), "blockPrivateAddresses") {
		t.Errorf("HTTP/3: want blockPrivateAddresses error, got %v", err)
	}
}
