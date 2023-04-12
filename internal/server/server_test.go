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
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hdecarne-github/certd/internal/certd"
	"github.com/hdecarne-github/certd/internal/server"
	"github.com/hdecarne-github/certd/pkg/keys/registry"
	"github.com/stretchr/testify/require"
)

const aboutServiceUrl = "http://localhost:10509/api/about"
const storeEntriesServiceUrl = "http://localhost:10509/api/store/entries"
const storeEntryDetailsServiceUrlPattern = "http://localhost:10509/api/store/entry/details/%s"
const storeCAsServiceUrl = "http://localhost:10509/api/store/cas"
const storeLocalIssuersServiceUrl = "http://localhost:10509/api/store/local/issuers"
const storeLocalGenerateServiceUrl = "http://localhost:10509/api/store/local/generate"
const storeRemoteGenerateServiceUrl = "http://localhost:10509/api/store/remote/generate"
const storeACMEGenerateServiceUrl = "http://localhost:10509/api/store/acme/generate"
const shutdownServiceUrl = "http://localhost:10509/api/shutdown"

func TestServer(t *testing.T) {
	// Accept test CA
	os.Setenv("LEGO_CA_CERTIFICATES", "../../pkg/certs/acme/testdata/certs/pebble.minica.pem")

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
	for i, keyProvider := range registry.KeyProviders() {
		for j, factory := range registry.StandardKeys(keyProvider) {
			testStoreGenerateLocal1(t, client, factory.Name(), (i*10)+(2*j))
			testStoreGenerateLocal2(t, client, factory.Name(), (i*10)+(2*j)+1)
		}
	}
	testStoreGenerateRemote(t, client)
	testStoreGenerateACME(t, client)
	testStoreEntries(t, client)
	testShutdown(t, client)
	shutdown.Wait()
	runServer(t, storePath, statePath, &shutdown)
	testStoreEntries(t, client)
	testStoreEntryDetails(t, client)
	testStoreLocalIssuers(t, client)
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

func testStoreEntries(t *testing.T, client *http.Client) {
	resp := doGet(t, client, storeEntriesServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	storeEntries := &server.StoreEntriesResponse{}
	decodeJsonResponse(t, resp, storeEntries)
	require.Equal(t, 18, len(storeEntries.Entries))
	require.Equal(t, "acme0", storeEntries.Entries[0].Name)
	require.Equal(t, "local0", storeEntries.Entries[1].Name)
	require.Equal(t, "local7", storeEntries.Entries[16].Name)
	require.Equal(t, "remote0", storeEntries.Entries[17].Name)
}

func testStoreEntryDetails(t *testing.T, client *http.Client) {
	const entryName = "local0"
	resp := doGet(t, client, fmt.Sprintf(storeEntryDetailsServiceUrlPattern, entryName))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	storeEntryDetails := &server.StoreEntryDetailsResponse{}
	decodeJsonResponse(t, resp, storeEntryDetails)
	require.Equal(t, entryName, storeEntryDetails.Name)
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

func testStoreLocalIssuers(t *testing.T, client *http.Client) {
	resp := doGet(t, client, storeLocalIssuersServiceUrl)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	storeLocalIssuers := &server.StoreLocalIssuersResponse{}
	decodeJsonResponse(t, resp, storeLocalIssuers)
	require.Equal(t, 8, len(storeLocalIssuers.Issuers))
	require.Equal(t, "local0", storeLocalIssuers.Issuers[0].Name)
	require.Equal(t, "local6", storeLocalIssuers.Issuers[7].Name)
}

const dnFormat = "CN=%s,OU=pki"
const localCertNameFormat = "local%d"

func testStoreGenerateLocal1(t *testing.T, client *http.Client, keyType string, id int) {
	name := fmt.Sprintf(localCertNameFormat, id)
	generateLocal := &server.StoreGenerateLocalRequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: name,
			CA:   "Local",
		},
		DN:        fmt.Sprintf(dnFormat, name),
		KeyType:   keyType,
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

func testStoreGenerateLocal2(t *testing.T, client *http.Client, keyType string, id int) {
	issuer := fmt.Sprintf(localCertNameFormat, id-1)
	name := fmt.Sprintf(localCertNameFormat, id)
	generateLocal := &server.StoreGenerateLocalRequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: name,
			CA:   "Local",
		},
		DN:        fmt.Sprintf(dnFormat, name),
		KeyType:   keyType,
		Issuer:    issuer,
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

const remoteCertNameFormat = "remote%d"

func testStoreGenerateRemote(t *testing.T, client *http.Client) {
	name := fmt.Sprintf(remoteCertNameFormat, 0)
	generateRemote := &server.StoreGenerateRemoteRequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: name,
			CA:   "Remote",
		},
		DN:      fmt.Sprintf(dnFormat, name),
		KeyType: "ED25519",
	}
	resp := doPut(t, client, storeRemoteGenerateServiceUrl, generateRemote)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

const acmeCertNameFormat = "acme%d"

func testStoreGenerateACME(t *testing.T, client *http.Client) {
	name := fmt.Sprintf(acmeCertNameFormat, 0)
	generateACME := &server.StoreGenerateACMERequest{
		StoreGenerateRequest: server.StoreGenerateRequest{
			Name: name,
			CA:   "ACME:Test",
		},
		Domains: []string{"localhost"},
		KeyType: "ECDSA P-256",
	}
	resp := doPut(t, client, storeACMEGenerateServiceUrl, generateACME)
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func testShutdown(t *testing.T, client *http.Client) {
	resp := doGet(t, client, shutdownServiceUrl)
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
