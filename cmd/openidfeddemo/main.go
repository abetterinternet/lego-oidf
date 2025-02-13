package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/openidfederation01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/tgeoghegan/oidf-box/entity"
)

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func main() {
	leafEntity, err := setupEntities()
	if err != nil {
		log.Fatal(err)
	}

	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: "you@example.com",
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This CA URL is configured for a local instance of Pebble.
	// TODO(timg): this should be determined by fetching the issuer's OIDF EC and getting
	// acme_provider from its metadata
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-issuer-metadata
	config.CADirURL = "https://localhost:14000/dir"
	config.Certificate.KeyType = certcrypto.RSA2048

	// Disable TLS verification as Pebble's cert is self-signed
	defaultTransport, ok := config.HTTPClient.Transport.(*http.Transport)
	if ok {
		// Not sure why we do this clone business instead of just mutating
		// defaultTransport but this is what Lego CLI does
		tr := defaultTransport.Clone()
		tr.TLSClientConfig.InsecureSkipVerify = true
		config.HTTPClient.Transport = tr
	} else {
		log.Fatal("could not get default HTTP transport")
	}

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// We specify an HTTP port of 5002 and an TLS port of 5001 on all interfaces
	// because we aren't running as root and can't bind a listener to port 80 and 443
	// (used later when we attempt to pass challenges). Keep in mind that you still
	// need to proxy challenge traffic to port 5002 and 5001.
	err = client.Challenge.SetOpenIDFederation01Solver(openidfederation01.Solver{})
	if err != nil {
		log.Fatal(err)
	}

	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	log.Printf("obtaining cert for 'domain' %s", leafEntity.Identifier.String())

	request := certificate.ObtainRequest{
		// The struct field here is Domains but it really should be Identifiers in ACME parlance.
		Identifiers: []acme.Identifier{{Type: "openid-federation", Value: leafEntity.Identifier.String()}},
		Bundle:      true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	fmt.Printf("PEM certificate:\n%s", string(certificates.Certificate))

	// ... all done.
}

func setupEntities() (*entity.Entity, error) {
	// Set up a chain of OIDF entities to act as a trust anchor (trusted by all entities), an
	// intermediate and the ACME requestor
	trustAnchor, err := entity.NewAndServe("http://localhost:8001", entity.EntityOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to construct trust anchor: %w", err)
	}
	defer trustAnchor.CleanUp()

	intermediate, err := entity.NewAndServe("http://localhost:8002", entity.EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to construct intermediate: %w", err)
	}
	defer intermediate.CleanUp()

	leafEntity, err := entity.NewAndServe("http://localhost:8003", entity.EntityOptions{
		TrustAnchors: []string{"http://localhost:8001"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to construct leaf entity: %w", err)
	}
	defer leafEntity.CleanUp()

	// Create subordinations
	oidfClient := entity.NewOIDFClient()
	intermediateClient, err := oidfClient.NewFederationEndpoints(intermediate.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	if err := intermediateClient.AddSubordinates([]entity.Identifier{leafEntity.Identifier}); err != nil {
		return nil, fmt.Errorf("failed to subordinate leaf entity: %s", err)
	}
	leafEntity.AddSuperior(intermediate.Identifier)

	trustAnchorClient, err := oidfClient.NewFederationEndpoints(trustAnchor.Identifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create API client: %w", err)
	}
	if err := trustAnchorClient.AddSubordinates([]entity.Identifier{intermediate.Identifier}); err != nil {
		return nil, fmt.Errorf("failed to subordinate intermediate: %s", err)
	}
	intermediate.AddSuperior(trustAnchor.Identifier)

	return leafEntity, nil
}
