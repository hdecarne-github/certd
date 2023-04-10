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

package certd

import (
	"os"
	"testing"

	"github.com/hdecarne-github/certd/internal/config"
	"github.com/stretchr/testify/require"
)

func TestCmdline(t *testing.T) {
	runner := &testRunner{}

	// <command> version
	os.Args = []string{os.Args[0], "version"}
	err := Run(runner)
	require.NoError(t, err)
	require.Equal(t, 1, runner.versionCalls)

	// <command> server --config=../../certd.yaml
	os.Args = []string{os.Args[0], "server", "--config=../../certd.yaml"}
	err = Run(runner)
	require.NoError(t, err)
	require.Equal(t, 1, runner.serverCalls)
	require.NotNil(t, runner.lastServerConfig)
	require.Equal(t, "http://localhost:10509", runner.lastServerConfig.ServerURL)
	require.Equal(t, "/var/lib/certd/store", runner.lastServerConfig.StorePath)
	require.Equal(t, "/var/lib/certd/state", runner.lastServerConfig.StatePath)
	require.Equal(t, "acme.yaml", runner.lastServerConfig.ACMEConfig)

	// <command> server --config=../../certd.yaml --server-url=https://cert.mydomain.org --store-path=./store --state-path=./state
	os.Args = []string{os.Args[0], "server", "--config=../../certd.yaml", "--server-url=https://certd.mydomain.org", "--store-path=./store", "--state-path=./state"}
	err = Run(runner)
	require.NoError(t, err)
	require.Equal(t, 2, runner.serverCalls)
	require.NotNil(t, runner.lastServerConfig)
	require.Equal(t, "https://certd.mydomain.org", runner.lastServerConfig.ServerURL)
	require.Equal(t, "./store", runner.lastServerConfig.StorePath)
	require.Equal(t, "./state", runner.lastServerConfig.StatePath)
}

type testRunner struct {
	versionCalls     int
	serverCalls      int
	lastServerConfig *config.ServerConfig
}

func (runner *testRunner) Version() error {
	runner.versionCalls += 1
	return nil
}

func (runner *testRunner) Server(config *config.ServerConfig) error {
	runner.serverCalls += 1
	runner.lastServerConfig = config
	return nil
}
