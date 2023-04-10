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

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	config := Defaults()
	require.NotNil(t, config)
	// Globals
	require.Equal(t, false, config.Debug)
	require.Equal(t, false, config.Verbose)
	require.Equal(t, false, config.ANSI)
	// Server
	require.Equal(t, "http://localhost:10509", config.Server.ServerURL)
	require.Equal(t, "/var/lib/certd/store", config.Server.StorePath)
	require.Equal(t, "/var/lib/certd/state", config.Server.StatePath)
	require.Equal(t, "acme.yaml", config.Server.ACMEConfig)
	// CLI
	require.Equal(t, "http://localhost:10509", config.CLI.ServerURL)
}

func TestLoad(t *testing.T) {
	config, err := Load("./testdata/certd-test.yaml")
	require.NoError(t, err)
	require.NotNil(t, config)
	// Globals
	require.Equal(t, true, config.Debug)
	require.Equal(t, true, config.Verbose)
	require.Equal(t, true, config.ANSI)
	// Server
	require.Equal(t, "https://certd.mydomain.org", config.Server.ServerURL)
	require.Equal(t, "./store", config.Server.StorePath)
	require.Equal(t, "./state", config.Server.StatePath)
	require.Equal(t, "./acme.yaml", config.Server.ACMEConfig)
	// CLI
	require.Equal(t, "https://certd.mydomain.org", config.CLI.ServerURL)
}
