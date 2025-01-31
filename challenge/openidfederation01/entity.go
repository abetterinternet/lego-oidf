package openidfederation01

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Entity represents an OpenID Federation Entity.
type Entity struct {
	// identifier for the OpenID Federation Entity. Must be a URL using https scheme.
	// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.4
	identifier string
	// federationEntityKey is this entity's keys
	// https://openid.net/specs/openid-federation-1_0-41.html#section-1.2-3.44
	federationEntityKeys jose.JSONWebKeySet
	// certifiableKeys is the set of keys that this entity MAY request X.509 certificates for
	// https://peppelinux.github.io/draft-demarco-acme-openid-federation/draft-demarco-acme-openid-federation.html#name-requestor-metadata
	certifiableKeys jose.JSONWebKeySet
}

// NewEntity constructs a new Entity, generating keys as needed.
func NewEntity(identifier string) (Entity, error) {
	// Generate the federation entity keys. Hard code a single 2048 bit RSA key for now.
	federationEntityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to generate key: %w", err)
	}
	federationEntityKeys, err := privateJWKS([]interface{}{federationEntityKey})
	if err != nil {
		return Entity{}, fmt.Errorf("failed to construct JWKS for federation entity: %w", err)
	}

	// Generate the keys this entity may certify. Hard code one RSA key, one EC key.
	rsaKeyToCertify, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to generate RSA key to certify: %w", err)
	}

	ecKeyToCertify, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Entity{}, fmt.Errorf("failed to generate P256 key to certify: %w", err)
	}

	certifiableKeys, err := privateJWKS([]interface{}{rsaKeyToCertify, ecKeyToCertify})
	if err != nil {
		return Entity{}, fmt.Errorf("failed to construct JWKS for keys to certify: %w", err)
	}

	return Entity{
		identifier:           identifier,
		federationEntityKeys: federationEntityKeys,
		certifiableKeys:      certifiableKeys,
	}, nil
}

// EntityConfiguration constructs and signs an Entity Configuration for this Entity
func (e *Entity) EntityConfiguration() (*jose.JSONWebSignature, error) {
	ec := map[string]interface{}{
		// iss, sub, iat, exp, jwks are required
		"iss":  e.identifier,
		"sub":  e.identifier,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Unix() + 3600, // valid for 1 hour
		"jwks": publicJWKS(&e.federationEntityKeys),
		// TODO: authority_hints is REQUIRED for non trust anchors
		"metadata": map[string]interface{}{
			"acme_requestor": map[string]interface{}{
				"jwks": publicJWKS(&e.certifiableKeys),
				// OpenID Federation REQUIRES iss and sub
				"iss": e.identifier,
				"sub": e.identifier,
				// TODO: iat and exp are OPTIONAL, consider adding them
			},
		},
	}
	payload, err := json.Marshal(ec)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity configuration to JSON: %w", err)
	}

	if e.federationEntityKeys.Keys[0].KeyID == "" {
		panic("federation entity key KID should be set")
	}

	entityConfigurationSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       e.federationEntityKeys.Keys[0].Key,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				// "typ" required by OIDF
				jose.HeaderType: "entity-statement+jwt",
				// "kid" required by OIDF, and it's RECOMMENDED it be the RFC 7638 thumbprint
				"kid": e.federationEntityKeys.Keys[0].KeyID,
			},
		})
	if err != nil {
		return nil, fmt.Errorf("failed to construct JOSE signer: %w", err)
	}

	signed, err := entityConfigurationSigner.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("Failed to sign entity configuration: %w", err)
	}

	return signed, nil
}

// privateJWKS returns a JSONWebKeySet containing the public and private portions of provided keys
func privateJWKS(keys []interface{}) (jose.JSONWebKeySet, error) {
	privateJWKS := jose.JSONWebKeySet{}
	for _, key := range keys {
		jsonWebKey := jose.JSONWebKey{Key: key}

		thumbprint, err := jsonWebKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to compute thumbprint: %w", err)
		}
		kid := base64.URLEncoding.EncodeToString(thumbprint)
		jsonWebKey.KeyID = kid

		// Round trip via JSON to set alg and kty (there's gotta be a better way...)
		json, err := jsonWebKey.MarshalJSON()
		if err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to encode JSON Web Key to JSON: %w", err)
		}

		if err := jsonWebKey.UnmarshalJSON(json); err != nil {
			return jose.JSONWebKeySet{}, fmt.Errorf("failed to decode JSON Web Key from JSON: %w", err)
		}

		log.Printf("generated JWK:\n%s\n%+v", json, jsonWebKey)

		privateJWKS.Keys = append(privateJWKS.Keys, jsonWebKey)
	}

	return privateJWKS, nil
}

// publicJWKS returns a JSONWebKeySet containing only the public portion of jwks.
func publicJWKS(jwks *jose.JSONWebKeySet) jose.JSONWebKeySet {
	publicJWKS := jose.JSONWebKeySet{}
	for _, jsonWebKey := range jwks.Keys {
		publicJWKS.Keys = append(publicJWKS.Keys, jsonWebKey.Public())
	}

	return publicJWKS
}
