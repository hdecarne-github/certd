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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyIdentiferString(t *testing.T) {
	keyId1 := []byte{0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59}
	require.Equal(t, "88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:87:d1:d6:87:6b:7b:94:59", KeyIdentifierString(keyId1))
	keyId2 := []byte{0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59, 0x88, 0x1b, 0xd6, 0x08, 0x08, 0xe2, 0xef, 0x84, 0x74, 0xc7, 0x1c, 0x2c, 0x87, 0xd1, 0xd6, 0x87, 0x6b, 0x7b, 0x94, 0x59}
	require.Equal(t, "88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:87:d1:d6:87:6b:7b:94:59:88:1b:d6:08:08:e2:ef:84:74:c7:1c:2c:...", KeyIdentifierString(keyId2))
}
