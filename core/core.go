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

var DefaultSignatureAlgorithm = ECDSAWithSHA256

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

var LegacySignatureAlgorithms = map[SignatureAlgorithm]bool{
	SHA256WithRSA: true,
	SHA384WithRSA: true,
	SHA512WithRSA: true,
}

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
