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

const noCA = "CA = false"
const aCAWithoutPathLenConstraint = "CA = true"
const aCAWithPathLenConstraint = "CA = true, pathLenConstraint = 2"

func TestBasicConstraintsString(t *testing.T) {
	require.Equal(t, noCA, BasicConstraintsString(false, 0, false))
	require.Equal(t, aCAWithoutPathLenConstraint, BasicConstraintsString(true, -1, true))
	require.Equal(t, aCAWithoutPathLenConstraint, BasicConstraintsString(true, -1, false))
	require.Equal(t, aCAWithoutPathLenConstraint, BasicConstraintsString(true, 0, false))
	require.Equal(t, aCAWithPathLenConstraint, BasicConstraintsString(true, 2, false))
	require.Equal(t, aCAWithPathLenConstraint, BasicConstraintsString(true, 2, true))
}
