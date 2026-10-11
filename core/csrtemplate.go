package core

import "crypto/x509/pkix"

// CsrTemplate represents a template for creating a Certificate Signing Request (CSR).
type CsrTemplate struct {
	SignatureAlgorithm SignatureAlgorithm
	Subject            pkix.Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []string
	URIs               []string
	ExtraExtensions    []pkix.Extension
}
