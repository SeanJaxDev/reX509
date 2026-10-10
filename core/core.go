package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

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

type SignatureAlgorithm x509.SignatureAlgorithm

type CsrTemplate struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	Subject            pkix.Name
	DNSNames           []string
	EmailAddresses     []string
	IPAddresses        []string
	URIs               []string
	ExtraExtensions    []pkix.Extension
}
