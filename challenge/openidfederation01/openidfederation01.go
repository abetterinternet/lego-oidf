package openidfederation01

import (
	_ "encoding/base64"
	_ "encoding/json"
	_ "net"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	_ "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/log"
	_ "github.com/go-jose/go-jose/v4"
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

	entity, err := NewEntity(domain)
	if err != nil {
		return err
	}

	// Sign the token from the challenge
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-openid-federation-challenge
	signedToken, err := entity.SignChallenge(chall.Token)
	if err != nil {
		return err
	}

	// TODO(timg): Spec says sig is "a base64url encoding of a JWT, signing the token encoded in
	// UTF-8 with one of the keys published in the Requestor's acme_requestor metadata in its Entity
	// Configuration, as specified in Section 6.3.2. It is REQUIRED that this JWT include a kid
	// claim corresponding to a valid key."
	// This isn't really clear enough.
	// I assume we want the compact JWS here, per what either OIDC or OIDF say, but the
	// acme-oidf doc could be clear about it too
	compactSignedToken, err := signedToken.CompactSerialize()
	if err != nil {
		return err
	}

	// The token signed with the acme_requestor key now gets POSTed to the ACME server. That request
	// gets signed with an ACME account key per RFC 8555. This happens in the s.validate call below.
	challengePayload := map[string]interface{}{
		"sig": compactSignedToken,
		// TODO(timg): add OIDF trust_chain
	}

	log.Infof("[%s]: Generated challenge payload %+v for challenge %+v", domain, challengePayload, chall)

	// TODO(timg): do I need to marshal to JSON and base64url here before calling validate?
	// base64.URLEncoding.EncodeToString([]byte(jsonSignedToken))

	// Begin serving the OpenID Federation Entity Configuration so the issuer can find it during
	// validation
	if err := entity.ServeEntityConfiguration(); err != nil {
		return err
	}
	defer entity.CleanUp()
	log.Infof("[%s]: serving entity configuration, now validating", domain)

	return s.Validate(s.ACMEAPI, domain, chall, challengePayload)
}
