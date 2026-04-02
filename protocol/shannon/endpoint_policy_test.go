package shannon

import (
	"testing"

	"github.com/pokt-network/poktroll/pkg/polylog/polyzero"
	sharedtypes "github.com/pokt-network/poktroll/x/shared/types"
	"github.com/stretchr/testify/require"

	"github.com/pokt-network/path/gateway"
	"github.com/pokt-network/path/protocol"
)

func makeTestEndpoint(supplier, u string) (protocol.EndpointAddr, endpoint) {
	ep := protocolEndpoint{
		supplier:   supplier,
		defaultURL: u,
		rpcTypeURLs: map[sharedtypes.RPCType]string{
			sharedtypes.RPCType_JSON_RPC: u,
		},
	}
	return ep.Addr(), ep
}

func TestEndpointPolicy_RequireHTTPS(t *testing.T) {
	p := &Protocol{
		logger: polyzero.NewLogger(),
		endpointPolicy: gateway.EndpointPolicyConfig{
			RequireHTTPS: true,
		},
	}

	endpoints := make(map[protocol.EndpointAddr]endpoint)
	httpsAddr, httpsEp := makeTestEndpoint("pokt1secure", "https://secure.example.com")
	httpAddr, httpEp := makeTestEndpoint("pokt1insecure", "http://insecure.example.com")
	endpoints[httpsAddr] = httpsEp
	endpoints[httpAddr] = httpEp

	result := p.filterByEndpointPolicy(endpoints, sharedtypes.RPCType_JSON_RPC, p.logger)

	require.Len(t, result, 1)
	require.Contains(t, result, httpsAddr)
	require.NotContains(t, result, httpAddr)
}

func TestEndpointPolicy_RequireDomain(t *testing.T) {
	p := &Protocol{
		logger: polyzero.NewLogger(),
		endpointPolicy: gateway.EndpointPolicyConfig{
			RequireDomain: true,
		},
	}

	endpoints := make(map[protocol.EndpointAddr]endpoint)
	domainAddr, domainEp := makeTestEndpoint("pokt1domain", "https://node.example.com")
	ipv4Addr, ipv4Ep := makeTestEndpoint("pokt1ipv4", "https://62.84.183.58:8545")
	ipv6Addr, ipv6Ep := makeTestEndpoint("pokt1ipv6", "https://[::1]:8545")
	endpoints[domainAddr] = domainEp
	endpoints[ipv4Addr] = ipv4Ep
	endpoints[ipv6Addr] = ipv6Ep

	result := p.filterByEndpointPolicy(endpoints, sharedtypes.RPCType_JSON_RPC, p.logger)

	require.Len(t, result, 1)
	require.Contains(t, result, domainAddr)
	require.NotContains(t, result, ipv4Addr)
	require.NotContains(t, result, ipv6Addr)
}

func TestEndpointPolicy_BothPolicies(t *testing.T) {
	p := &Protocol{
		logger: polyzero.NewLogger(),
		endpointPolicy: gateway.EndpointPolicyConfig{
			RequireHTTPS:  true,
			RequireDomain: true,
		},
	}

	endpoints := make(map[protocol.EndpointAddr]endpoint)
	goodAddr, goodEp := makeTestEndpoint("pokt1good", "https://node.example.com")
	httpDomainAddr, httpDomainEp := makeTestEndpoint("pokt1httpdom", "http://node2.example.com")
	httpsIPAddr, httpsIPEp := makeTestEndpoint("pokt1httpsip", "https://62.84.183.58:8545")
	httpIPAddr, httpIPEp := makeTestEndpoint("pokt1httpip", "http://10.0.0.1:8545")
	endpoints[goodAddr] = goodEp
	endpoints[httpDomainAddr] = httpDomainEp
	endpoints[httpsIPAddr] = httpsIPEp
	endpoints[httpIPAddr] = httpIPEp

	result := p.filterByEndpointPolicy(endpoints, sharedtypes.RPCType_JSON_RPC, p.logger)

	require.Len(t, result, 1)
	require.Contains(t, result, goodAddr, "only HTTPS + domain should pass")
}

func TestEndpointPolicy_NoPolicies(t *testing.T) {
	p := &Protocol{
		logger:         polyzero.NewLogger(),
		endpointPolicy: gateway.EndpointPolicyConfig{},
	}

	endpoints := make(map[protocol.EndpointAddr]endpoint)
	a1, e1 := makeTestEndpoint("pokt1a", "http://10.0.0.1:8545")
	a2, e2 := makeTestEndpoint("pokt1b", "https://node.example.com")
	endpoints[a1] = e1
	endpoints[a2] = e2

	result := p.filterByEndpointPolicy(endpoints, sharedtypes.RPCType_JSON_RPC, p.logger)

	require.Len(t, result, 2, "no policies enabled, all endpoints pass")
}

func TestEndpointPolicy_WebsocketSecure(t *testing.T) {
	p := &Protocol{
		logger: polyzero.NewLogger(),
		endpointPolicy: gateway.EndpointPolicyConfig{
			RequireHTTPS: true,
		},
	}

	endpoints := make(map[protocol.EndpointAddr]endpoint)
	wssAddr, wssEp := makeTestEndpoint("pokt1wss", "wss://ws.example.com")
	wsAddr, wsEp := makeTestEndpoint("pokt1ws", "ws://ws.example.com")
	endpoints[wssAddr] = wssEp
	endpoints[wsAddr] = wsEp

	// Use UNKNOWN RPC type so it falls back to PublicURL
	result := p.filterByEndpointPolicy(endpoints, sharedtypes.RPCType_UNKNOWN_RPC, p.logger)

	require.Len(t, result, 1)
	require.Contains(t, result, wssAddr)
}

func TestIsRawIP(t *testing.T) {
	tests := []struct {
		url    string
		expect bool
	}{
		{"https://node.example.com", false},
		{"https://sub.node.example.com:8545", false},
		{"https://62.84.183.58:8545", true},
		{"https://62.84.183.58", true},
		{"http://10.0.0.1:8545", true},
		{"https://[::1]:8545", true},
		{"https://[2001:db8::1]:8545", true},
		{"https://localhost:8545", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			require.Equal(t, tt.expect, isRawIP(tt.url))
		})
	}
}

func TestIsSecureURL(t *testing.T) {
	tests := []struct {
		url    string
		expect bool
	}{
		{"https://example.com", true},
		{"http://example.com", false},
		{"wss://example.com", true},
		{"ws://example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			require.Equal(t, tt.expect, isSecureURL(tt.url))
		})
	}
}
