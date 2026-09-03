package cycletls

import (
	"crypto/tls"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
)

// Test that getTransport no longer panics when dialTLS returns (conn, nil)
// due to a cached connection/transport already being present for the address.
func TestGetTransport_NoPanicWhenCachedConnPresent(t *testing.T) {
	// Create a new roundTripper
	rtIface := newRoundTripper(Browser{})

	// Type assert to concrete type to access internals
	rt, ok := rtIface.(*roundTripper)
	if !ok {
		t.Fatalf("expected *roundTripper, got %T", rtIface)
	}

	// Build a simple HTTPS request
	req, err := http.NewRequest("GET", "https://example.com/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	// Determine the addr key used by roundTripper
	addr := rt.getDialTLSAddr(req)

	// Simulate a previously established (cached) TLS connection and transport
	c1, _ := net.Pipe()
	defer c1.Close()
	rt.cachedConnections[addr] = c1
	rt.cachedTransports[addr] = &http.Transport{}

	// Ensure no panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("did not expect panic: %v", r)
		}
	}()

	if err := rt.getTransport(req, addr); err != nil {
		t.Fatalf("getTransport returned error: %v", err)
	}
}

func TestTLSHandshakesForDifferentHostsRunConcurrently(t *testing.T) {
	clearAllConnections()
	t.Cleanup(clearAllConnections)

	handshakeStarted := make(chan time.Time, 2)
	newServer := func() *httptest.Server {
		server := httptest.NewUnstartedServer(stdhttp.HandlerFunc(func(response stdhttp.ResponseWriter, _ *stdhttp.Request) {
			response.WriteHeader(stdhttp.StatusOK)
		}))
		server.TLS = &tls.Config{
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakeStarted <- time.Now()
				time.Sleep(400 * time.Millisecond)
				return nil, nil
			},
		}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server
	}

	firstServer := newServer()
	secondServer := newServer()
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/150.0.0.0 Safari/537.36"
	client, err := newClientWithReuse(Browser{
		UserAgent:          userAgent,
		InsecureSkipVerify: true,
		ForceHTTP1:         true,
	}, 5, true, userAgent, true)
	if err != nil {
		t.Fatal(err)
	}

	var wait sync.WaitGroup
	errors := make(chan error, 2)
	for _, targetURL := range []string{firstServer.URL, secondServer.URL} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response, requestErr := client.Get(targetURL)
			if requestErr == nil {
				response.Body.Close()
			}
			errors <- requestErr
		}()
	}
	wait.Wait()
	close(errors)
	for requestErr := range errors {
		if requestErr != nil {
			t.Fatal(requestErr)
		}
	}

	firstStart := <-handshakeStarted
	secondStart := <-handshakeStarted
	difference := secondStart.Sub(firstStart)
	if difference < 0 {
		difference = -difference
	}
	if difference > 250*time.Millisecond {
		t.Fatalf("TLS handshakes were serialized: start times differed by %s", difference)
	}
}

func TestInvalidRequestReturnsErrorWithoutStoppingServer(t *testing.T) {
	request := cycleTLSRequest{
		RequestID: "invalid-request",
		Options: Options{
			URL:     "://bad-url",
			Method:  "get",
			Headers: map[string]string{},
		},
	}

	result := processRequest(request)
	if result.err == nil {
		t.Fatal("expected invalid URL to return an error")
	}
}
