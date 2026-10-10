package core

import (
	"crypto/x509"
	"crypto/x509/pkix"
)

type CsrTemplate struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	Subject 		  pkix.Name
	DNSNames 		  []string
	EmailAddresses 	  []string
	IPAddresses 		  []string
	URIs 			  []string
	ExtraExtensions 	  []pkix.Extension
}