/*
 * Copyright (c) 2023 Holger de Carne and contributors, All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package certs

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// Read X.509 certificates from the given file.
func ReadCertificates(filename string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates from file '%s' (cause: %w)", filename, err)
	}
	decoded, err := decodeCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates from file '%s' (cause: %w)", filename, err)
	}
	return decoded, nil
}

func decodeCertificates(bytes []byte) ([]*x509.Certificate, error) {
	decoded := make([]*x509.Certificate, 0)
	block, rest := pem.Decode(bytes)
	for block != nil {
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return decoded, err
		}
		decoded = append(decoded, certs...)
		block, rest = pem.Decode(rest)
	}
	if len(decoded) == 0 {
		certs, err := x509.ParseCertificates(bytes)
		if err != nil {
			return decoded, err
		}
		decoded = append(decoded, certs...)
	}
	return decoded, nil
}

// Fetch X.509 certificates via the given URL.
func FetchCertificates(url string) ([]*x509.Certificate, error) {
	bytes, err := fetchBytes(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from url '%s' (cause: %w)", url, err)
	}
	decoded, err := decodeCertificates(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates from url '%s' (cause: %w)", url, err)
	}
	return decoded, nil
}

func fetchBytes(url string) ([]byte, error) {
	rsp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http status: %s", rsp.Status)
	}
	bytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// Get the X.509 certificates used for encrypting the connection to the given server.
//
// The server protocol must be TLS based (e.g. https, ldaps). The certificates are
// retrieved during the TLS handshake.
func ServerCertificates(network string, addr string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial(network, addr, &tls.Config{InsecureSkipVerify: true, VerifyPeerCertificate: verifyPeerCertificate})
	if conn != nil {
		defer conn.Close()
	}
	if err == nil {
		return nil, fmt.Errorf("failed to retrieve server certificates (%s:%s)", network, addr)
	}
	cve, ok := err.(*tls.CertificateVerificationError)
	if !ok {
		return nil, err
	}
	return cve.UnverifiedCertificates, nil
}

func verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	err := tls.CertificateVerificationError{}
	err.UnverifiedCertificates = make([]*x509.Certificate, 0)
	for _, rawCert := range rawCerts {
		decodedCerts, _ := decodeCertificates(rawCert)
		if decodedCerts != nil {
			err.UnverifiedCertificates = append(err.UnverifiedCertificates, decodedCerts...)
		}
	}
	err.Err = fmt.Errorf("%d peer certifcates received", len(err.UnverifiedCertificates))
	return &err
}

// Parse a Distinguished Name (DN) string.
func ParseDN(dn string) (*pkix.Name, error) {
	ldapDN, err := ldap.ParseDN(dn)
	if err != nil {
		return nil, fmt.Errorf("invalid DN '%s' (cause: %w)", dn, err)
	}
	rdns := make([]pkix.RelativeDistinguishedNameSET, 0)
	for _, ldapRDN := range ldapDN.RDNs {
		rdn := make([]pkix.AttributeTypeAndValue, 0)
		for _, ldapRDNAttribute := range ldapRDN.Attributes {
			rdnType, err := parseLdapRDNType(ldapRDNAttribute.Type)
			if err != nil {
				return nil, err
			}
			rdn = append(rdn, pkix.AttributeTypeAndValue{Type: rdnType, Value: ldapRDNAttribute.Value})
		}
		rdns = append(rdns, rdn)
	}
	parsedDN := &pkix.Name{}
	parsedDN.FillFromRDNSequence((*pkix.RDNSequence)(&rdns))
	return parsedDN, nil
}

func parseLdapRDNType(ldapRDNType string) (asn1.ObjectIdentifier, error) {
	switch ldapRDNType {
	case "CN":
		return []int{2, 5, 4, 3}, nil
	case "SERIALNUMBER":
		return []int{2, 5, 4, 5}, nil
	case "C":
		return []int{2, 5, 4, 6}, nil
	case "L":
		return []int{2, 5, 4, 7}, nil
	case "ST":
		return []int{2, 5, 4, 8}, nil
	case "STREET":
		return []int{2, 5, 4, 9}, nil
	case "O":
		return []int{2, 5, 4, 10}, nil
	case "OU":
		return []int{2, 5, 4, 11}, nil
	case "POSTALCODE":
		return []int{2, 5, 4, 17}, nil
	case "UID":
		return []int{0, 9, 2342, 19200300, 100, 1, 1}, nil
	case "DC":
		return []int{0, 9, 2342, 19200300, 100, 1, 25}, nil
	}
	return nil, fmt.Errorf("unrecognized RDN type '%s'", ldapRDNType)
}
