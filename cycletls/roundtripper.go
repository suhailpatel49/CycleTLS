package cycletls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	http "github.com/Danny-Dasilva/fhttp"
	http2 "github.com/Danny-Dasilva/fhttp/http2"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	uquic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"time"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type roundTripper struct {
	sync.Mutex

	// Per-address mutexes for preventing concurrent transport creation
	addressMutexes   map[string]*sync.Mutex
	addressMutexLock sync.Mutex

	// TLS fingerprinting options
	JA3              string
	JA4r             string // JA4 raw format with explicit cipher/extension values
	HTTP2Fingerprint string
	QUICFingerprint  string
	USpec            *uquic.QUICSpec // UQuic QUIC specification for HTTP3 fingerprinting
	DisableGrease    bool

	// Browser identification
	UserAgent   string
	HeaderOrder []string

	// Connection options
	TLSConfig          *utls.Config
	InsecureSkipVerify bool
	ServerName         string
	Cookies            []Cookie
	ForceHTTP1         bool
	ForceHTTP3         bool

	// TLS 1.3 specific options
	TLS13AutoRetry bool

	// Caching
	cachedConnections    map[string]net.Conn
	cachedTransports     map[string]http.RoundTripper
	transportLastUsed    map[string]time.Time
	lastTransportCleanup time.Time
	http3Transport       *http3.Transport

	dialer proxy.ContextDialer
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Apply cookies to the request
	for _, properties := range rt.Cookies {
		cookie := &http.Cookie{
			Name:       properties.Name,
			Value:      properties.Value,
			Path:       properties.Path,
			Domain:     properties.Domain,
			Expires:    properties.JSONExpires.Time,
			RawExpires: properties.RawExpires,
			MaxAge:     properties.MaxAge,
			HttpOnly:   properties.HTTPOnly,
			Secure:     properties.Secure,
			Raw:        properties.Raw,
			Unparsed:   properties.Unparsed,
		}
		req.AddCookie(cookie)
	}

	// Apply header order if specified (for regular headers, not pseudo-headers).
	//
	// When HeaderOrder is non-empty we:
	//   1. Place the user-agent under the lowercase key so fhttp's header-order
	//      logic can position it deterministically.
	//   2. Run the request headers through MarshalHeader for case-insensitive
	//      ordering, then convert back via ConvertHttpHeader.
	//   3. Pin the order via the http.HeaderOrderKey sentinel.
	//
	// When HeaderOrder is empty we preserve the legacy behaviour of setting
	// the canonical "User-Agent" key and leaving the rest of the headers
	// untouched, which avoids surprising case changes for callers that did
	// not opt into ordered headers.
	//
	// Pseudo-header order (http.PHeaderOrderKey) is set in index.go based on
	// UserAgent parsing and must not be overwritten here.
	if len(rt.HeaderOrder) > 0 {
		delete(req.Header, "User-Agent")
		delete(req.Header, "user-agent")
		req.Header["user-agent"] = []string{rt.UserAgent}

		req.Header = ConvertHttpHeader(MarshalHeader(req.Header, rt.HeaderOrder))
		req.Header[http.HeaderOrderKey] = rt.HeaderOrder
	} else {
		req.Header.Set("User-Agent", rt.UserAgent)
	}

	// Get address for dialing
	addr := rt.getDialTLSAddr(req)

	// Check if we need HTTP/3 - matches reference implementation pattern
	if rt.ForceHTTP3 {
		return rt.makeHTTP3Request(req)
	}

	// Use cached transport if available, otherwise create a new one.
	transport := rt.cachedTransport(addr)
	if transport == nil {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}
		transport = rt.cachedTransport(addr)
	}

	// Perform the request
	return transport.RoundTrip(req)
}

func (rt *roundTripper) cachedTransport(addr string) http.RoundTripper {
	rt.Lock()
	now := time.Now()
	if now.Sub(rt.lastTransportCleanup) >= time.Minute {
		for cachedAddr, lastUsed := range rt.transportLastUsed {
			if now.Sub(lastUsed) <= 5*time.Minute {
				continue
			}
			if closer, ok := rt.cachedTransports[cachedAddr].(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
			delete(rt.cachedTransports, cachedAddr)
			if conn := rt.cachedConnections[cachedAddr]; conn != nil {
				_ = conn.Close()
				delete(rt.cachedConnections, cachedAddr)
			}
			delete(rt.transportLastUsed, cachedAddr)
		}
		rt.lastTransportCleanup = now
	}
	transport := rt.cachedTransports[addr]
	if transport != nil {
		rt.transportLastUsed[addr] = now
	}
	rt.Unlock()
	return transport
}

func (rt *roundTripper) getTransport(req *http.Request, addr string) error {
	switch strings.ToLower(req.URL.Scheme) {
	case "http":
		rt.Lock()
		rt.cachedTransports[addr] = &http.Transport{
			DialContext:         rt.dialer.DialContext,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
		}
		rt.Unlock()
		return nil
	case "https":
	default:
		return fmt.Errorf("invalid URL scheme: [%v]", req.URL.Scheme)
	}

	// Use per-address mutex to serialize transport creation and avoid races
	addressMutex := rt.getAddressMutex(addr)
	addressMutex.Lock()
	defer addressMutex.Unlock()

	// Double-check if transport was created while we were waiting for the lock
	if rt.cachedTransport(addr) != nil {
		// Another goroutine already created the transport
		return nil
	}

	// Establish TLS connection
	_, err := rt.dialTLS(req.Context(), "tcp", addr)
	switch err {
	case errProtocolNegotiated:
		// Transport and connection have been negotiated and cached by dialTLS
		// Nothing else to do here.
	case nil:
		// A cached connection/transport already exists (e.g., created by another goroutine).
		// Treat as success instead of panicking.
		// No action needed; RoundTrip will use the cached transport.
	default:
		return err
	}

	return nil
}

func (rt *roundTripper) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	cachedConn := rt.cachedConnections[addr]
	if cachedConn != nil {
		delete(rt.cachedConnections, addr)
	}
	rt.Unlock()

	// Give the negotiated connection to the transport once. The transport owns
	// connection reuse and reconnects after a server closes an idle connection.
	if cachedConn != nil {
		return cachedConn, nil
	}

	// Establish raw connection
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Extract host from address
	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}
	// Determine SNI to use (custom serverName takes precedence)
	serverName := host
	if rt.ServerName != "" {
		serverName = rt.ServerName
	}

	var spec *utls.ClientHelloSpec
	var helloID utls.ClientHelloID
	var proactivelyUpgraded bool // Track if we proactively upgraded TLS 1.2 to 1.3

	// Determine which fingerprint to use
	if rt.QUICFingerprint != "" {
		// Use QUIC fingerprint
		spec, err = QUICStringToSpec(rt.QUICFingerprint, rt.UserAgent, rt.ForceHTTP1)
		if err != nil {
			return nil, err
		}
	} else if rt.JA3 != "" {
		// Check if we should proactively upgrade TLS 1.2 to TLS 1.3
		if rt.TLS13AutoRetry && strings.HasPrefix(rt.JA3, "771,") {
			// Use TLS 1.3 compatible spec to avoid retry cycle
			spec, err = StringToTLS13CompatibleSpec(rt.JA3, rt.UserAgent, rt.ForceHTTP1)
			proactivelyUpgraded = true
		} else {
			// Use original JA3 fingerprint
			spec, err = StringToSpec(rt.JA3, rt.UserAgent, rt.ForceHTTP1)
		}
		if err != nil {
			return nil, err
		}
	} else if rt.JA4r != "" {
		// Use JA4r (raw) fingerprint
		spec, err = JA4RStringToSpec(rt.JA4r, rt.UserAgent, rt.ForceHTTP1, rt.DisableGrease, serverName)
		if err != nil {
			return nil, err
		}
	} else {
		parsedUserAgent := parseUserAgent(rt.UserAgent)
		switch parsedUserAgent.UserAgent {
		case chrome:
			spec = ModernChromeSpec(rt.ForceHTTP1)
		case firefox:
			helloID = utls.HelloFirefox_Auto
		default:
			spec, err = StringToSpec(DefaultChrome_JA3, rt.UserAgent, rt.ForceHTTP1)
			if err != nil {
				return nil, err
			}
		}
	}

	// Create TLS client
	clientHelloID := utls.HelloCustom
	if helloID.Client != "" {
		clientHelloID = helloID
	}
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         serverName,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
	}, clientHelloID)

	// Apply TLS fingerprint
	if spec != nil {
		if err := conn.ApplyPreset(spec); err != nil {
			return nil, err
		}
	}

	// Perform TLS handshake
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()

		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			// Check if TLS 1.3 retry is enabled
			if rt.TLS13AutoRetry {
				// Automatically retry with TLS 1.3 compatible curves
				return rt.retryWithTLS13CompatibleCurves(ctx, network, addr, host)
			}
			return nil, fmt.Errorf("conn.Handshake() error for TLS 1.3 (retry disabled): %+v", err)
		}

		// If we proactively upgraded to TLS 1.3 and it failed, try falling back to original TLS 1.2 JA3
		if proactivelyUpgraded && rt.JA3 != "" {
			return rt.retryWithOriginalTLS12JA3(ctx, network, addr, host)
		}

		return nil, fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}

	rt.Lock()
	defer rt.Unlock()

	// If transport already exists, return connection
	if rt.cachedTransports[addr] != nil {
		return conn, nil
	}

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		// Use HTTP/2 fingerprint if specified
		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			// Parse and apply HTTP/2 fingerprint
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			// Apply HTTP/2 fingerprint settings
			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = &http2Transport
	default:
		// HTTP/1.x transport
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:      rt.dialTLS,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
		}
	}

	// Cache the connection for future use
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

// retryWithTLS13CompatibleCurves retries the TLS connection with TLS 1.3 compatible curves
func (rt *roundTripper) retryWithTLS13CompatibleCurves(ctx context.Context, network, addr, host string) (net.Conn, error) {
	// Establish raw connection for retry
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var spec *utls.ClientHelloSpec

	// Use TLS 1.3 compatible spec based on the original fingerprint type
	if rt.QUICFingerprint != "" {
		// For QUIC, we'll use the original spec but this could be enhanced
		spec, err = QUICStringToSpec(rt.QUICFingerprint, rt.UserAgent, rt.ForceHTTP1)
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC spec for TLS 1.3 retry: %v", err)
		}
	} else if rt.JA3 != "" {
		// Use TLS 1.3 compatible JA3 spec
		spec, err = StringToTLS13CompatibleSpec(rt.JA3, rt.UserAgent, rt.ForceHTTP1)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible JA3 spec: %v", err)
		}
	} else if rt.JA4r != "" {
		// For JA4r, we'll use a fallback to default Chrome with TLS 1.3 compatible curves
		spec, err = StringToTLS13CompatibleSpec(DefaultChrome_JA3, rt.UserAgent, rt.ForceHTTP1)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible JA4 fallback spec: %v", err)
		}
	} else {
		// Default to TLS 1.3 compatible Chrome fingerprint
		spec, err = StringToTLS13CompatibleSpec(DefaultChrome_JA3, rt.UserAgent, rt.ForceHTTP1)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS 1.3 compatible default spec: %v", err)
		}
	}

	// Create TLS client for retry
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
	}, utls.HelloCustom)

	// Apply TLS 1.3 compatible fingerprint
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply TLS 1.3 compatible preset: %v", err)
	}

	// Perform TLS handshake for retry
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("TLS 1.3 compatible handshake failed: %+v", err)
	}

	rt.Lock()
	defer rt.Unlock()

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint for TLS 1.3 retry: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = &http2Transport
	default:
		// HTTP/1.x transport
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:      rt.dialTLS,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
		}
	}

	// Cache the successful TLS 1.3 connection
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

// retryWithOriginalTLS12JA3 retries the TLS connection with the original TLS 1.2 JA3
func (rt *roundTripper) retryWithOriginalTLS12JA3(ctx context.Context, network, addr, host string) (net.Conn, error) {
	// Establish raw connection for fallback to original TLS 1.2 JA3
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Use original TLS 1.2 JA3 spec (no upgrade)
	spec, err := StringToSpec(rt.JA3, rt.UserAgent, rt.ForceHTTP1)
	if err != nil {
		return nil, fmt.Errorf("failed to create original TLS 1.2 JA3 spec: %v", err)
	}

	// Create TLS client for fallback
	conn := utls.UClient(rawConn, &utls.Config{
		ServerName:         host,
		OmitEmptyPsk:       true,
		InsecureSkipVerify: rt.InsecureSkipVerify,
	}, utls.HelloCustom)

	// Apply original TLS 1.2 fingerprint
	if err := conn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("failed to apply original TLS 1.2 preset: %v", err)
	}

	// Perform TLS handshake for fallback
	if err = conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("original TLS 1.2 handshake failed: %+v", err)
	}

	rt.Lock()
	defer rt.Unlock()

	// Create appropriate transport based on negotiated protocol
	switch conn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		// HTTP/2 transport
		parsedUserAgent := parseUserAgent(rt.UserAgent)

		var http2Transport http2.Transport
		if rt.HTTP2Fingerprint != "" {
			h2Fingerprint, err := NewHTTP2Fingerprint(rt.HTTP2Fingerprint)
			if err != nil {
				return nil, fmt.Errorf("failed to parse HTTP/2 fingerprint for TLS 1.2 fallback: %v", err)
			}

			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}

			h2Fingerprint.Apply(&http2Transport)
		} else {
			http2Transport = http2.Transport{
				DialTLS:     rt.dialTLSHTTP2,
				PushHandler: &http2.DefaultPushHandler{},
				Navigator:   parsedUserAgent.UserAgent,
			}
		}

		rt.cachedTransports[addr] = &http2Transport
	default:
		// HTTP/1.x transport
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext:      rt.dialTLS,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
		}
	}

	// Cache the successful TLS 1.2 fallback connection
	rt.cachedConnections[addr] = conn

	return nil, errProtocolNegotiated
}

func (rt *roundTripper) dialTLSHTTP2(network, addr string, _ *utls.Config) (net.Conn, error) {
	return rt.dialTLS(context.Background(), network, addr)
}

func (rt *roundTripper) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // Default HTTPS port
}

// getAddressMutex returns a mutex for the specific address to serialize transport creation
func (rt *roundTripper) getAddressMutex(addr string) *sync.Mutex {
	rt.addressMutexLock.Lock()
	defer rt.addressMutexLock.Unlock()

	if rt.addressMutexes == nil {
		rt.addressMutexes = make(map[string]*sync.Mutex)
	}

	if mu, exists := rt.addressMutexes[addr]; exists {
		return mu
	}

	mu := &sync.Mutex{}
	rt.addressMutexes[addr] = mu
	return mu
}

// CloseIdleConnections closes connections that have been idle for too long
// If selectedAddr is provided, only close connections not matching this address
func (rt *roundTripper) CloseIdleConnections() {
	rt.Lock()

	for addr, transport := range rt.cachedTransports {
		if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
		delete(rt.cachedTransports, addr)
	}
	for addr, conn := range rt.cachedConnections {
		_ = conn.Close()
		delete(rt.cachedConnections, addr)
	}
	rt.transportLastUsed = make(map[string]time.Time)
	if rt.http3Transport != nil {
		_ = rt.http3Transport.Close()
		rt.http3Transport = nil
	}
	rt.Unlock()

	rt.addressMutexLock.Lock()
	rt.addressMutexes = make(map[string]*sync.Mutex)
	rt.addressMutexLock.Unlock()
}

func newRoundTripper(browser Browser, dialer ...proxy.ContextDialer) http.RoundTripper {
	var contextDialer proxy.ContextDialer
	if len(dialer) > 0 {
		contextDialer = dialer[0]
	} else {
		contextDialer = proxy.Direct
	}

	return &roundTripper{
		dialer:             contextDialer,
		JA3:                browser.JA3,
		JA4r:               browser.JA4r,
		HTTP2Fingerprint:   browser.HTTP2Fingerprint,
		QUICFingerprint:    browser.QUICFingerprint,
		USpec:              browser.USpec, // Add USpec field initialization
		DisableGrease:      browser.DisableGrease,
		UserAgent:          browser.UserAgent,
		HeaderOrder:        browser.HeaderOrder,
		TLSConfig:          browser.TLSConfig,
		ServerName:         browser.ServerName,
		Cookies:            browser.Cookies,
		cachedTransports:   make(map[string]http.RoundTripper),
		cachedConnections:  make(map[string]net.Conn),
		transportLastUsed:  make(map[string]time.Time),
		InsecureSkipVerify: browser.InsecureSkipVerify,
		ForceHTTP1:         browser.ForceHTTP1,
		ForceHTTP3:         browser.ForceHTTP3,

		// TLS 1.3 specific options
		TLS13AutoRetry: browser.TLS13AutoRetry,
	}
}

// makeHTTP3Request performs an HTTP/3 request using one reusable transport.
func (rt *roundTripper) makeHTTP3Request(req *http.Request) (*http.Response, error) {
	tlsConfig := ConvertUtlsConfig(rt.TLSConfig)
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	// Apply custom SNI if provided
	if rt.ServerName != "" {
		tlsConfig.ServerName = rt.ServerName
	}

	rt.Lock()
	if rt.http3Transport == nil {
		rt.http3Transport = &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout:           30 * time.Second,
				MaxIdleTimeout:                 90 * time.Second,
				KeepAlivePeriod:                15 * time.Second,
				InitialStreamReceiveWindow:     512 * 1024,
				MaxStreamReceiveWindow:         2 * 1024 * 1024,
				InitialConnectionReceiveWindow: 1024 * 1024,
				MaxConnectionReceiveWindow:     4 * 1024 * 1024,
				MaxIncomingStreams:             100,
				MaxIncomingUniStreams:          100,
				EnableDatagrams:                false,
				DisablePathMTUDiscovery:        false,
				Allow0RTT:                      false,
			},
		}
	}
	roundTripper := rt.http3Transport
	rt.Unlock()

	// Convert fhttp.Request to net/http.Request
	stdReq := &stdhttp.Request{
		Method:           req.Method,
		URL:              req.URL,
		Proto:            req.Proto,
		ProtoMajor:       req.ProtoMajor,
		ProtoMinor:       req.ProtoMinor,
		Header:           ConvertFhttpHeader(req.Header),
		Body:             req.Body,
		GetBody:          req.GetBody,
		ContentLength:    req.ContentLength,
		TransferEncoding: req.TransferEncoding,
		Close:            req.Close,
		Host:             req.Host,
		Form:             req.Form,
		PostForm:         req.PostForm,
		MultipartForm:    req.MultipartForm,
		Trailer:          ConvertFhttpHeader(req.Trailer),
		RemoteAddr:       req.RemoteAddr,
		RequestURI:       req.RequestURI,
		TLS:              nil,
		Cancel:           req.Cancel,
		Response:         nil,
	}

	// Use the RoundTripper to make the request
	stdResp, err := roundTripper.RoundTrip(stdReq)
	if err != nil {
		return nil, err
	}

	// Convert back to fhttp.Response
	return &http.Response{
		Status:           stdResp.Status,
		StatusCode:       stdResp.StatusCode,
		Proto:            stdResp.Proto,
		ProtoMajor:       stdResp.ProtoMajor,
		ProtoMinor:       stdResp.ProtoMinor,
		Header:           ConvertHttpHeader(stdResp.Header),
		Body:             stdResp.Body,
		ContentLength:    stdResp.ContentLength,
		TransferEncoding: stdResp.TransferEncoding,
		Close:            stdResp.Close,
		Uncompressed:     stdResp.Uncompressed,
		Trailer:          ConvertHttpHeader(stdResp.Trailer),
		Request:          req,
		TLS:              nil,
	}, nil
}

// Default JA3 fingerprint for Chrome
const DefaultChrome_JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
