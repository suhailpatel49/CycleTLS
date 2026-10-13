package cycletls

import (
	"net"
	"os"
	"testing"

	http "github.com/Danny-Dasilva/fhttp"
)

const resolverTestJA3 = "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-51-57-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0"

func TestResolverOptionSelectsCloudflareDialer(t *testing.T) {
	if resolverFor("") != nil || resolverFor("google") != nil {
		t.Fatal("only \"cloudflare\" selects a custom resolver")
	}

	system := Browser{JA3: resolverTestJA3, UserAgent: "test"}
	cloudflare := system
	cloudflare.Resolver = "cloudflare"
	if generateClientKey(system, 10, false, "") == generateClientKey(cloudflare, 10, false, "") {
		t.Fatal("the resolver must be part of the client pool key")
	}

	client, err := createNewClient(cloudflare, 10, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	rt := client.Transport.(*roundTripper)
	if dialer, ok := rt.dialer.(*net.Dialer); !ok || dialer.Resolver != cloudflareResolver {
		t.Fatalf("direct dialer does not use the Cloudflare resolver: %#v", rt.dialer)
	}
	if rt.Resolver != "cloudflare" {
		t.Fatal("HTTP/3 needs the resolver on the round tripper")
	}

	// With a proxy, the proxy resolves the target name.
	client, err = createNewClient(cloudflare, 10, false, "test", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := client.Transport.(*roundTripper).dialer.(*net.Dialer); ok {
		t.Fatal("proxied requests must not use the direct Cloudflare dialer")
	}
}

// Run with CYCLETLS_LIVE_DNS_URL=https://cloudflare-quic.com/ go test -run Live ./
// The URL must support HTTP/2 and HTTP/3.
func TestCloudflareResolverLive(t *testing.T) {
	url := os.Getenv("CYCLETLS_LIVE_DNS_URL")
	if url == "" {
		t.Skip("set CYCLETLS_LIVE_DNS_URL to run")
	}

	for _, forceHTTP3 := range []bool{false, true} {
		request := func() error {
			browser := Browser{JA3: resolverTestJA3, UserAgent: "test", Resolver: "cloudflare", ForceHTTP3: forceHTTP3}
			client, err := createNewClient(browser, 20, true, "test")
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

		saved := cloudflareServers
		cloudflareServers = []string{"127.0.0.1:1"}
		err := request()
		cloudflareServers = saved
		if err == nil {
			t.Fatalf("forceHTTP3=%t: request worked without a Cloudflare server, so it did not use the Cloudflare resolver", forceHTTP3)
		}
		if err := request(); err != nil {
			t.Fatalf("forceHTTP3=%t: %v", forceHTTP3, err)
		}
	}
}
