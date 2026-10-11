package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

// SignatureAlgorithm is a wrapper around x509.SignatureAlgorithm to allow for custom methods.
var (
	SHA256WithRSA    = SignatureAlgorithm(x509.SHA256WithRSA)
	SHA384WithRSA    = SignatureAlgorithm(x509.SHA384WithRSA)
	SHA512WithRSA    = SignatureAlgorithm(x509.SHA512WithRSA)
	SHA256WithRSAPSS = SignatureAlgorithm(x509.SHA256WithRSAPSS)
	SHA384WithRSAPSS = SignatureAlgorithm(x509.SHA384WithRSAPSS)
	SHA512WithRSAPSS = SignatureAlgorithm(x509.SHA512WithRSAPSS)
	ECDSAWithSHA256  = SignatureAlgorithm(x509.ECDSAWithSHA256)
	ECDSAWithSHA384  = SignatureAlgorithm(x509.ECDSAWithSHA384)
	ECDSAWithSHA512  = SignatureAlgorithm(x509.ECDSAWithSHA512)
	PureEd25519      = SignatureAlgorithm(x509.PureEd25519)
	MLDSA44          = SignatureAlgorithm(x509.MLDSA44)
	MLDSA65          = SignatureAlgorithm(x509.MLDSA65)
	MLDSA87          = SignatureAlgorithm(x509.MLDSA87)
)

// DefaultSignatureAlgorithm is the default signature algorithm used for signing certificates.
var DefaultSignatureAlgorithm = ECDSAWithSHA256

// ContemporarySignatureAlgorithms is a map of signature algorithms that are considered
// contemporary and secure.
var ContemporarySignatureAlgorithms = map[SignatureAlgorithm]bool{
	ECDSAWithSHA256:  true,
	ECDSAWithSHA384:  true,
	ECDSAWithSHA512:  true,
	PureEd25519:      true,
	SHA256WithRSAPSS: true,
	SHA384WithRSAPSS: true,
	SHA512WithRSAPSS: true,
	MLDSA44:          true,
	MLDSA65:          true,
	MLDSA87:          true,
}

// LegacySignatureAlgorithms is a map of signature algorithms that are considered legacy
// and less secure.
var LegacySignatureAlgorithms = map[SignatureAlgorithm]bool{
	SHA256WithRSA: true,
	SHA384WithRSA: true,
	SHA512WithRSA: true,
}

// UnsupportedSignatureAlgorithms is a map of signature algorithms that are considered unsupported
// and should not be used.
var UnsupportedSignatureAlgorithms = map[SignatureAlgorithm]bool{
	SignatureAlgorithm(x509.MD2WithRSA):    true,
	SignatureAlgorithm(x509.MD5WithRSA):    true,
	SignatureAlgorithm(x509.SHA1WithRSA):   true,
	SignatureAlgorithm(x509.DSAWithSHA1):   true,
	SignatureAlgorithm(x509.ECDSAWithSHA1): true,
}

// SignatureAlgorithm is a wrapper around x509.SignatureAlgorithm to allow for custom methods.
type SignatureAlgorithm x509.SignatureAlgorithm

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
