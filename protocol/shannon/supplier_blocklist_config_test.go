package shannon

import (
	"testing"

	"github.com/pokt-network/poktroll/pkg/polylog/polyzero"
	"github.com/stretchr/testify/require"

	"github.com/pokt-network/path/gateway"
	"github.com/pokt-network/path/protocol"
)

func TestIsSupplierConfigBlocked(t *testing.T) {
	unifiedConfig := &gateway.UnifiedServicesConfig{
		Services: []gateway.ServiceConfig{
			{
				ID: protocol.ServiceID("poly"),
				BlockedSuppliers: []string{
					"pokt1hm2d2vsc9jnv663ep0h02yrvst3mrnpn57ww2u",
					"pokt1anotherone",
				},
			},
			{
				ID: protocol.ServiceID("eth"),
				// No blocked suppliers
			},
		},
	}

	p := &Protocol{
		logger:                polyzero.NewLogger(),
		unifiedServicesConfig: unifiedConfig,
	}

	// Blocked supplier on poly should be blocked
	require.True(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("poly"),
		"pokt1hm2d2vsc9jnv663ep0h02yrvst3mrnpn57ww2u",
	))

	// Second blocked supplier on poly should also be blocked
	require.True(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("poly"),
		"pokt1anotherone",
	))

	// Non-blocked supplier on poly should NOT be blocked
	require.False(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("poly"),
		"pokt1legitimate",
	))

	// Blocked supplier on poly should NOT be blocked on eth (different service)
	require.False(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("eth"),
		"pokt1hm2d2vsc9jnv663ep0h02yrvst3mrnpn57ww2u",
	))

	// Unknown service should not block anything
	require.False(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("unknown"),
		"pokt1hm2d2vsc9jnv663ep0h02yrvst3mrnpn57ww2u",
	))
}

func TestIsSupplierConfigBlocked_NilConfig(t *testing.T) {
	p := &Protocol{
		logger:                polyzero.NewLogger(),
		unifiedServicesConfig: nil,
	}

	require.False(t, p.isSupplierConfigBlocked(
		protocol.ServiceID("poly"),
		"pokt1hm2d2vsc9jnv663ep0h02yrvst3mrnpn57ww2u",
	))
}

func TestGetBlockedSuppliers(t *testing.T) {
	blocked := []string{"pokt1bad1", "pokt1bad2"}
	unifiedConfig := &gateway.UnifiedServicesConfig{
		Services: []gateway.ServiceConfig{
			{
				ID:               protocol.ServiceID("poly"),
				BlockedSuppliers: blocked,
			},
			{
				ID: protocol.ServiceID("eth"),
			},
		},
	}

	p := &Protocol{
		logger:                polyzero.NewLogger(),
		unifiedServicesConfig: unifiedConfig,
	}

	// Service with blocked suppliers
	result := p.getBlockedSuppliers(protocol.ServiceID("poly"))
	require.Equal(t, blocked, result)

	// Service without blocked suppliers
	result = p.getBlockedSuppliers(protocol.ServiceID("eth"))
	require.Nil(t, result)

	// Unknown service
	result = p.getBlockedSuppliers(protocol.ServiceID("unknown"))
	require.Nil(t, result)
}