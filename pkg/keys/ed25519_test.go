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

package keys

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestED25519KeyPair(t *testing.T) {
	kpfs := KeyPairFactories(ED25519)
	for _, kpf := range kpfs {
		fmt.Printf("Generating %s", kpf.Name())
		start := time.Now()
		keypair, err := kpf.New()
		elapsed := time.Since(start)
		fmt.Printf(" (took: %s)\n", elapsed)
		require.NoError(t, err)
		require.NotNil(t, keypair)
	}
}
