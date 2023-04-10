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

package server_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hdecarne-github/certd/internal/certd"
	"github.com/stretchr/testify/require"
)

const aboutServiceUrl = "http://localhost:10509/api/about"

func TestServer(t *testing.T) {
	workDir, err := os.MkdirTemp("", "certd")
	require.NoError(t, err)
	defer os.RemoveAll(workDir)
	storePath := filepath.Join(workDir, "store")
	statePath := filepath.Join(workDir, "state")
	go func() {
		os.Args = []string{"certd", "--debug", "server", "--config=../../certd.yaml", "--store-path=" + storePath, "--state-path=" + statePath}
		err := certd.Run(nil)
		require.NoError(t, err)
	}()
	client := &http.Client{}
	testAbout(t, client)
}

func testAbout(t *testing.T, client *http.Client) {
	resp := doGet(t, client, aboutServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func doGet(t *testing.T, client *http.Client, url string) *http.Response {
	for retryCount := 0; ; retryCount += 1 {
		time.Sleep(250 * time.Millisecond)
		resp, err := client.Get(url)
		if err == nil {
			return resp
		}
		if retryCount >= 5 {
			require.NoError(t, err)
		}
	}
}
