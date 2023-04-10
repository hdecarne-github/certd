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
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadPEMCertificates(t *testing.T) {
	certs, err := ReadCertificates("./testdata/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestReadDERCertificates(t *testing.T) {
	certs, err := ReadCertificates("./testdata/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchPEMCertificates(t *testing.T) {
	certs, err := FetchCertificates("https://letsencrypt.org/certs/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchDERCertificates(t *testing.T) {
	certs, err := FetchCertificates("https://letsencrypt.org/certs/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestServerCertificates(t *testing.T) {
	certs, err := ServerCertificates("tcp", "valid-isrgrootx1.letsencrypt.org:443")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 2, len(certs))
}

func TestParseDN(t *testing.T) {
	dn := &pkix.Name{
		CommonName:         "CommonName",
		Locality:           []string{"Locality"},
		Country:            []string{"Country"},
		Organization:       []string{"Organization"},
		OrganizationalUnit: []string{"OrganizationUnit"},
		PostalCode:         []string{"PostalCode"},
		Province:           []string{"Province"},
		SerialNumber:       "SerialNumber",
		StreetAddress:      []string{"StreetAddress"},
	}
	parsed, err := ParseDN(dn.String())
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, dn.String(), parsed.String())
}
