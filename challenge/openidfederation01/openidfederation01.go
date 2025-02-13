package openidfederation01

import (
	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	"github.com/tgeoghegan/oidf-box/entity"
	"github.com/tgeoghegan/oidf-box/openidfederation01"
)

// ValidateFunc is a callback into solver_manager.go used to poll for the ACME server validating our
// challenge response. This is rather awkward, but is done to fit the existing object model of DNS
// and HTTP challenges and their providers.
type ValidateFunc func(core *api.Core, domain string, chlg acme.Challenge, response interface{}) error

type Solver struct {
	Validate ValidateFunc
	ACMEAPI  *api.Core
}

// Solve satisifes resolver.Solver
func (s *Solver) Solve(authz acme.Authorization) error {
	domain := challenge.GetTargetedDomain(authz)
	log.Infof("[%s] acme: Trying to solve openid-federation-01", domain)

	chall, err := challenge.FindChallenge(challenge.OPENIDFEDERATION01, authz)
	if err != nil {
		return err
	}

	entity, err := entity.New(domain, entity.EntityOptions{
		IsACMERequestor: true,
	})
	if err != nil {
		return err
	}

	// Sign the token from the challenge and represent that as a compact JWS
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-openid-federation-challenge
	signedToken, err := entity.SignChallenge(chall.Token)
	if err != nil {
		return err
	}

	compactSignedToken, err := signedToken.CompactSerialize()
	if err != nil {
		return err
	}

	// The token signed with the acme_requestor key now gets POSTed to the ACME server. That request
	// gets signed with an ACME account key per RFC 8555. This happens in the s.validate call below.
	challengePayload := openidfederation01.ChallengeResponse{
		// TODO(timg): add trust_chain
		Sig: compactSignedToken,
	}

	return s.Validate(s.ACMEAPI, domain, chall, challengePayload)
}
