package openidfederation01

import (
	"fmt"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	"github.com/tgeoghegan/oidf-box/oidfclient"
	"github.com/tgeoghegan/oidf-box/openidfederation01"
)

// ValidateFunc is a callback into solver_manager.go used to poll for the ACME server validating our
// challenge response. This is rather awkward, but is done to fit the existing object model of DNS
// and HTTP challenges and their providers.
type ValidateFunc func(core *api.Core, domain string, chlg acme.Challenge, response any) error

type Solver struct {
	Validate ValidateFunc
	ACMEAPI  *api.Core
	Entities []*oidfclient.FederationEndpoints
}

// Solve satisifes resolver.Solver
func (s *Solver) Solve(authz acme.Authorization) error {
	domain := challenge.GetTargetedDomain(authz)
	log.Infof("[%s] acme: Trying to solve openid-federation-01", domain)

	chall, err := challenge.FindChallenge(challenge.OPENIDFEDERATION01, authz)
	if err != nil {
		return err
	}

	// Figure out which entity to solve the challenge with
	var challengeSolver *oidfclient.FederationEndpoints
	for _, entity := range s.Entities {
		// Double check that the identifier in the authz has the correct type, though it should not
		// be possible to get here otherwise.
		if authz.Identifier.Type != "openid-federation" {
			return fmt.Errorf("unexpected identifier %v in authz", authz)
		}
		if authz.Identifier.Value == entity.Entity.Subject {
			challengeSolver = entity
			break
		}
	}

	signedToken, err := challengeSolver.SignChallenge(chall.Token)
	if err != nil {
		return err
	}

	// The token signed with the acme_requestor key now gets POSTed to the ACME server. That request
	// gets signed with an ACME account key per RFC 8555. This happens in the s.validate call below.
	challengePayload := openidfederation01.ChallengeResponse{
		// TODO(timg): add trust_chain
		Sig: signedToken,
	}

	return s.Validate(s.ACMEAPI, domain, chall, challengePayload)
}
