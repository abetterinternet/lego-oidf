package cmd

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/stretchr/testify/assert"
)

func Test_merge(t *testing.T) {
	testCases := []struct {
		desc        string
		prevDomains []acme.Identifier
		nextDomains []acme.Identifier
		expected    []acme.Identifier
	}{
		{
			desc:        "all empty",
			prevDomains: []acme.Identifier{},
			nextDomains: []acme.Identifier{},
			expected:    []acme.Identifier{},
		},
		{
			desc:        "next empty",
			prevDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
			nextDomains: []acme.Identifier{},
			expected:    []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
		},
		{
			desc:        "prev empty",
			prevDomains: []acme.Identifier{},
			nextDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
			expected:    []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
		},
		{
			desc:        "merge append",
			prevDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
			nextDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("c"), acme.NewIdentifier("d")},
			expected:    []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c"), acme.NewIdentifier("d")},
		},
		{
			desc:        "merge same",
			prevDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
			nextDomains: []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
			expected:    []acme.Identifier{acme.NewIdentifier("a"), acme.NewIdentifier("b"), acme.NewIdentifier("c")},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual := merge(test.prevDomains, test.nextDomains)
			assert.Equal(t, test.expected, actual)
		})
	}
}

func Test_needRenewal(t *testing.T) {
	testCases := []struct {
		desc     string
		x509Cert *x509.Certificate
		days     int
		expected bool
	}{
		{
			desc: "30 days, NotAfter now",
			x509Cert: &x509.Certificate{
				NotAfter: time.Now(),
			},
			days:     30,
			expected: true,
		},
		{
			desc: "30 days, NotAfter 31 days",
			x509Cert: &x509.Certificate{
				NotAfter: time.Now().Add(31*24*time.Hour + 1*time.Second),
			},
			days:     30,
			expected: false,
		},
		{
			desc: "30 days, NotAfter 30 days",
			x509Cert: &x509.Certificate{
				NotAfter: time.Now().Add(30 * 24 * time.Hour),
			},
			days:     30,
			expected: true,
		},
		{
			desc: "0 days, NotAfter 30 days: only the day of the expiration",
			x509Cert: &x509.Certificate{
				NotAfter: time.Now().Add(30 * 24 * time.Hour),
			},
			days:     0,
			expected: false,
		},
		{
			desc: "-1 days, NotAfter 30 days: always renew",
			x509Cert: &x509.Certificate{
				NotAfter: time.Now().Add(30 * 24 * time.Hour),
			},
			days:     -1,
			expected: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			actual := needRenewal(test.x509Cert, "foo.com", test.days)

			assert.Equal(t, test.expected, actual)
		})
	}
}
