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

package registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRegistry(t *testing.T) {
	for _, providerName := range KeyProviders() {
		standardKeys := StandardKeys(providerName)
		require.NotNil(t, standardKeys)
		require.NotEqual(t, 0, len(standardKeys))
		for _, standardKey := range standardKeys {
			key := StandardKey(standardKey.Name())
			require.NotNil(t, key)
			require.Equal(t, standardKey.Name(), key.Name())
		}
	}
}
