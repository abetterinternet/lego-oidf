package openidfederation01

import (
	_ "net"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/challenge"
	_ "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	_ "github.com/go-jose/go-jose/v4"
)

// Challenge implements resolver.Solver for `openid-federation-01` challenges
type Challenge struct{}

// Solve satisifes resolver.Solver
func (c *Challenge) Solve(authz acme.Authorization) error {
	domain := challenge.GetTargetedDomain(authz)
	log.Infof("[%s] acme: Trying to solve openid-federation-01", domain)

	_, err := challenge.FindChallenge(challenge.OPENIDFEDERATION01, authz)
	if err != nil {
		return err
	}

	entity, err := NewEntity(domain)
	if err != nil {
		return err
	}

	signedEntityConfiguration, err := entity.EntityConfiguration()
	if err != nil {
		return err
	}

	log.Infof("constructed EC: %+v", signedEntityConfiguration.FullSerialize())

	panic("not implemented")

	// Start serving OpenID EC

	// sign token with private key

	// post signed token to challenge

	// Generate the Key Authorization for the challenge
	// keyAuth, err := c.core.GetKeyAuthorization(chlng.Token)
	// if err != nil {
	// 	return err
	// }

	// err = c.provider.Present(authz.Identifier.Value, chlng.Token, keyAuth)
	// if err != nil {
	// 	return fmt.Errorf("[%s] acme: error presenting token: %w", domain, err)
	// }
	// defer func() {
	// 	err := c.provider.CleanUp(authz.Identifier.Value, chlng.Token, keyAuth)
	// 	if err != nil {
	// 		log.Warnf("[%s] acme: cleaning up failed: %v", domain, err)
	// 	}
	// }()

	// chlng.KeyAuthorization = keyAuth
	// return c.validate(c.core, domain, chlng)

}
