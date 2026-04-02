package shannon

import (
	"net"
	"net/url"
	"strings"

	"github.com/pokt-network/poktroll/pkg/polylog"
	sharedtypes "github.com/pokt-network/poktroll/x/shared/types"

	"github.com/pokt-network/path/protocol"
)

// filterByEndpointPolicy applies operator-level endpoint security policies.
// Returns the filtered endpoints and the count of rejected endpoints.
// If no policies are enabled, returns the original endpoints unchanged.
func (p *Protocol) filterByEndpointPolicy(
	endpoints map[protocol.EndpointAddr]endpoint,
	rpcType sharedtypes.RPCType,
	logger polylog.Logger,
) map[protocol.EndpointAddr]endpoint {
	policy := p.endpointPolicy
	if !policy.RequireHTTPS && !policy.RequireDomain {
		return endpoints
	}

	filtered := make(map[protocol.EndpointAddr]endpoint, len(endpoints))
	rejectedHTTPS := 0
	rejectedDomain := 0

	for addr, ep := range endpoints {
		epURL := ep.GetURL(rpcType)
		if epURL == "" {
			epURL = ep.PublicURL()
		}

		if policy.RequireHTTPS && !isSecureURL(epURL) {
			rejectedHTTPS++
			logger.Debug().
				Str("endpoint", string(addr)).
				Str("url", epURL).
				Msg("Rejected endpoint: does not use HTTPS/WSS (endpoint_policy.require_https)")
			continue
		}

		if policy.RequireDomain && isRawIP(epURL) {
			rejectedDomain++
			logger.Debug().
				Str("endpoint", string(addr)).
				Str("url", epURL).
				Msg("Rejected endpoint: uses raw IP instead of domain (endpoint_policy.require_domain)")
			continue
		}

		filtered[addr] = ep
	}

	if rejectedHTTPS > 0 || rejectedDomain > 0 {
		logger.Info().
			Int("rejected_no_https", rejectedHTTPS).
			Int("rejected_raw_ip", rejectedDomain).
			Int("remaining", len(filtered)).
			Msg("Endpoint policy filtered out non-compliant endpoints")
	}

	return filtered
}

// isSecureURL returns true if the URL uses a secure scheme (https or wss).
func isSecureURL(rawURL string) bool {
	return strings.HasPrefix(rawURL, "https://") || strings.HasPrefix(rawURL, "wss://")
}

// isRawIP returns true if the URL's host is an IP address rather than a domain name.
func isRawIP(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	if host == "" {
		return false
	}

	return net.ParseIP(host) != nil
}
