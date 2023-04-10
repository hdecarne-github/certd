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
package extensions

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtKeyUsageString(t *testing.T) {
	noUsage := []x509.ExtKeyUsage{}
	noUnknownUsage := []asn1.ObjectIdentifier{}
	require.Equal(t, "-", ExtKeyUsageString(noUsage, noUnknownUsage))
	aUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	anUnknownUsage := []asn1.ObjectIdentifier{asn1.ObjectIdentifier([]int{1, 2, 3, 4})}
	require.Equal(t, "1.2.3.4, Any", ExtKeyUsageString(aUsage, anUnknownUsage))
}
