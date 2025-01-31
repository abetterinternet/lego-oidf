package openidfederation01

import (
	"net"

	"github.com/go-acme/lego/v4/acme"
	_ "github.com/go-acme/lego/v4/challenge"
)

// ProviderServer implements challenge.Provider for the `openid-federation-01`
// challenge. It serves an OpenID Federation Entity Configuration to satisfy
// a challenge.
type ProviderServer struct {
	address string
}

// NewProviderServer creates a new Provider server which binds the provided port
// on the provided interface.
func NewProviderServer(iface, port string) *ProviderServer {
	return &ProviderServer{address: net.JoinHostPort(iface, port)}
}

// Present satisfies challenge.Provider
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	// TODO: implement! What do we do with token and keyAuth here?
	panic("not implemented")
}

// CleanUp satisifes challenge.Provider
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	// TODO: implement!
	panic("not implemented")
}

// Challenge implements resolver.Solver for `openid-federation-01` challenges
type Challenge struct{}

// Solve satisifes resolver.Solver
func (c *Challenge) Solve(authorization acme.Authorization) error {
	panic("not implemented")
}
