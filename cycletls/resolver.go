package cycletls

import (
	"context"
	"net"
	"sync/atomic"
)

// cloudflareServers are used in turn, so a retried query goes to the other server.
var cloudflareServers = []string{"1.1.1.1:53", "1.0.0.1:53"}
var cloudflareServerIndex atomic.Uint32

// cloudflareResolver resolves names through Cloudflare DNS instead of the system resolver.
var cloudflareResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		server := cloudflareServers[cloudflareServerIndex.Add(1)%uint32(len(cloudflareServers))]
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server)
	},
}

// resolverFor returns the resolver for an Options.Resolver value,
// or nil for the system resolver.
func resolverFor(name string) *net.Resolver {
	if name == "cloudflare" {
		return cloudflareResolver
	}
	return nil
}
