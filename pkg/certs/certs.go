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
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
)

// Read X.509 certificates from the given file.
func ReadCerts(filename string) ([]*x509.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificates from file '%s' (cause: %w)", filename, err)
	}
	decoded, err := decodeCerts(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificates from file '%s' (cause: %w)", filename, err)
	}
	return decoded, nil
}

func decodeCerts(bytes []byte) ([]*x509.Certificate, error) {
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
func FetchCerts(url string) ([]*x509.Certificate, error) {
	bytes, err := fetchBytes(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from url '%s' (cause: %w)", url, err)
	}
	decoded, err := decodeCerts(bytes)
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
func ServerCerts(network string, addr string) ([]*x509.Certificate, error) {
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
		decodedCerts, _ := decodeCerts(rawCert)
		if decodedCerts != nil {
			err.UnverifiedCertificates = append(err.UnverifiedCertificates, decodedCerts...)
		}
	}
	err.Err = fmt.Errorf("%d peer certifcates received", len(err.UnverifiedCertificates))
	return &err
}
