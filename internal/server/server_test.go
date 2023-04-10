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
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hdecarne-github/certd/internal/certd"
	"github.com/hdecarne-github/certd/internal/server"
	"github.com/stretchr/testify/require"
)

const aboutServiceUrl = "http://localhost:10509/api/about"
const storeEntriesServiceUrl = "http://localhost:10509/api/store/entries"
const storeCAsServiceUrl = "http://localhost:10509/api/store/cas"
const storeLocalGenerateServiceUrl = "http://localhost:10509/api/store/local/generate"
const shutdownServiceUrl = "http://localhost:10509/api/shutdown"

func TestServer(t *testing.T) {
	workDir, err := os.MkdirTemp("", "certd")
	require.NoError(t, err)
	defer os.RemoveAll(workDir)
	storePath := filepath.Join(workDir, "store")
	statePath := filepath.Join(workDir, "state")
	var shutdown sync.WaitGroup
	runServer(t, storePath, statePath, &shutdown)
	client := &http.Client{}
	testAbout(t, client)
	testStoreCAs(t, client)
	testStoreGenerateLocal1(t, client)
	testStoreGenerateLocal2(t, client)
	testShutdown(t, client)
	shutdown.Wait()
	runServer(t, storePath, statePath, &shutdown)
	testStoreEntries(t, client)
	testShutdown(t, client)
	shutdown.Wait()
}

func runServer(t *testing.T, storePath string, statePath string, shutdown *sync.WaitGroup) {
	shutdown.Add(1)
	go func() {
		os.Args = []string{"certd", "server", "--config=testdata/certd-test.yaml", "--store-path=" + storePath, "--state-path=" + statePath}
		err := certd.Run(nil)
		require.NoError(t, err)
		shutdown.Done()
	}()
}

func testAbout(t *testing.T, client *http.Client) {
	resp := doGet(t, client, aboutServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	about := &server.AboutResponse{}
	decodeJsonResponse(t, resp, about)
	require.NotEmpty(t, about.Version)
	require.NotEmpty(t, about.Timestamp)
}

func testStoreCAs(t *testing.T, client *http.Client) {
	resp := doGet(t, client, storeCAsServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	storeCAs := &server.StoreCAsResponse{}
	decodeJsonResponse(t, resp, storeCAs)
	require.Equal(t, 3, len(storeCAs.CAs))
	require.Equal(t, "Local", storeCAs.CAs[0].Name)
	require.Equal(t, "Remote", storeCAs.CAs[1].Name)
	require.Equal(t, "ACME:Test", storeCAs.CAs[2].Name)
}

func testStoreGenerateLocal1(t *testing.T, client *http.Client) {
	generateLocal := &server.StoreGenerateLocalRequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: "cert1",
			CA:   "Local",
		},
		DN:        "CN=cert1,OU=pki",
		KeyType:   "ED25519",
		ValidFrom: time.Now(),
		ValidTo:   time.Now().Add(24 * 60 * time.Minute),
		KeyUsage: server.KeyUsageExtensionSpec{
			ExtensionSpec: server.ExtensionSpec{Enabled: true},
			CertSign:      true,
			CRLSign:       true,
		},
		BasicConstraint: server.BasicConstraintExtensionSpec{
			ExtensionSpec: server.ExtensionSpec{Enabled: true},
			CA:            true,
			PathLen:       -1,
		},
	}
	resp := doPut(t, client, storeLocalGenerateServiceUrl, generateLocal)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func testStoreGenerateLocal2(t *testing.T, client *http.Client) {
	generateLocal := &server.StoreGenerateLocalRequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: "cert2",
			CA:   "Local",
		},
		DN:        "CN=cert2,OU=pki",
		KeyType:   "ED25519",
		Issuer:    "cert1",
		ValidFrom: time.Now(),
		ValidTo:   time.Now().Add(24 * 60 * time.Minute),
		KeyUsage: server.KeyUsageExtensionSpec{
			ExtensionSpec:   server.ExtensionSpec{Enabled: true},
			KeyEncipherment: true,
		},
		ExtKeyUsage: server.ExtKeyUsageExtensionSpec{
			ExtensionSpec: server.ExtensionSpec{Enabled: true},
			ServerAuth:    true,
		},
	}
	resp := doPut(t, client, storeLocalGenerateServiceUrl, generateLocal)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func testShutdown(t *testing.T, client *http.Client) {
	resp := doGet(t, client, shutdownServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func testStoreEntries(t *testing.T, client *http.Client) {
	resp := doGet(t, client, storeEntriesServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	storeEntries := &server.StoreEntriesResponse{}
	decodeJsonResponse(t, resp, storeEntries)
	require.Equal(t, 2, len(storeEntries.Entries))
	require.Equal(t, "cert1", storeEntries.Entries[0].Name)
	require.Equal(t, "cert2", storeEntries.Entries[1].Name)
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

func doPut(t *testing.T, client *http.Client, url string, v any) *http.Response {
	body, err := json.Marshal(v)
	require.NoError(t, err)
	for retryCount := 0; ; retryCount += 1 {
		time.Sleep(250 * time.Millisecond)
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		require.NoError(t, err)
		resp, err := client.Do(req)
		if err == nil {
			return resp
		}
		if retryCount >= 5 {
			require.NoError(t, err)
		}
	}
}

func decodeJsonResponse(t *testing.T, resp *http.Response, v any) {
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(t, err)
}
