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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadPEMCerts(t *testing.T) {
	certs, err := ReadCerts("./testdata/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestReadDERCerts(t *testing.T) {
	certs, err := ReadCerts("./testdata/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchPEMCerts(t *testing.T) {
	certs, err := FetchCerts("https://letsencrypt.org/certs/isrgrootx1.pem")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestFetchDERCerts(t *testing.T) {
	certs, err := FetchCerts("https://letsencrypt.org/certs/isrgrootx1.der")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 1, len(certs))
}

func TestServerCerts(t *testing.T) {
	certs, err := ServerCerts("tcp", "valid-isrgrootx1.letsencrypt.org:443")
	require.NoError(t, err)
	require.NotNil(t, certs)
	require.Equal(t, 2, len(certs))
}
