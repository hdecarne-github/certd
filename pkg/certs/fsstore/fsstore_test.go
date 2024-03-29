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

package fsstore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/pkg/certs/local"
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/hdecarne-github/certd/pkg/keys/ecdsa"
	"github.com/hdecarne-github/certd/pkg/keys/ed25519"
	"github.com/hdecarne-github/certd/pkg/keys/rsa"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const storeHome = "fsstore"

func TestCreateAndOpenFSStore(t *testing.T) {
	home := mkhome(t)
	defer os.RemoveAll(home)
	storePath := filepath.Join(home, storeHome)
	// try to open non-existing store
	store1, err := Open(storePath)
	require.Error(t, err)
	require.Nil(t, store1)
	// create new store
	store2, err := Init(storePath)
	require.NoError(t, err)
	require.NotNil(t, store2)
	// try to create existing store
	store3, err := Init(storePath)
	require.Error(t, err)
	require.Nil(t, store3)
	// open existing store
	store4, err := Open(storePath)
	require.NoError(t, err)
	require.NotNil(t, store4)
}

func TestCreateLocalCertificateRSA(t *testing.T) {
	home := mkhome(t)
	defer os.RemoveAll(home)
	storePath := filepath.Join(home, storeHome)
	createLocalCertficate(t, storePath, rsa.StandardKeys())
	store := openStore(t, storePath)
	entryCount := traverseStoreEntries(t, store)
	require.Equal(t, 6, entryCount)
}

func TestCreateLocalCertificateECDSA(t *testing.T) {
	home := mkhome(t)
	defer os.RemoveAll(home)
	storePath := filepath.Join(home, storeHome)
	createLocalCertficate(t, storePath, ecdsa.StandardKeys())
	store := openStore(t, storePath)
	entryCount := traverseStoreEntries(t, store)
	require.Equal(t, 8, entryCount)
}

func TestCreateLocalCertificateED25519(t *testing.T) {
	home := mkhome(t)
	defer os.RemoveAll(home)
	storePath := filepath.Join(home, storeHome)
	createLocalCertficate(t, storePath, ed25519.StandardKeys())
	store := openStore(t, storePath)
	entryCount := traverseStoreEntries(t, store)
	require.Equal(t, 2, entryCount)
}

var localCATemplate = &x509.Certificate{
	SerialNumber: big.NewInt(1),
	Subject: pkix.Name{
		Organization:  []string{"Organization"},
		Country:       []string{"Country"},
		Province:      []string{"Province"},
		Locality:      []string{"Locality"},
		StreetAddress: []string{"Street address"},
		PostalCode:    []string{"Postal code"},
	},
	NotBefore:             time.Now(),
	NotAfter:              time.Now().AddDate(1, 0, 0),
	IsCA:                  true,
	ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	BasicConstraintsValid: true,
}

var localServerTemplate = &x509.Certificate{
	SerialNumber: big.NewInt(2),
	Subject: pkix.Name{
		Organization:  []string{"Organization"},
		Country:       []string{"Country"},
		Province:      []string{"Province"},
		Locality:      []string{"Locality"},
		StreetAddress: []string{"Street address"},
		PostalCode:    []string{"Postal code"},
	},
	NotBefore:    time.Now(),
	NotAfter:     time.Now().AddDate(1, 0, 0),
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

func createLocalCertficate(t *testing.T, path string, kpfs []keys.KeyPairFactory) {
	store, err := Init(path)
	require.NoError(t, err)
	require.NotNil(t, store)
	for _, kpf := range kpfs {
		// create self-signed root certificate
		lcf1 := local.NewLocalCertificateFactory(localCATemplate, kpf, nil, nil)
		entry1, err := store.CreateCertificate(kpf.Name()+"-1", lcf1)
		require.NoError(t, err)
		require.NotNil(t, entry1)
		// create signed certificate
		entry1Certificate, err := entry1.Certificate()
		require.NoError(t, err)
		require.NotNil(t, entry1Certificate)
		entry1Key, err := entry1.Key()
		require.NoError(t, err)
		require.NotNil(t, entry1Key)
		lcf2 := local.NewLocalCertificateFactory(localServerTemplate, kpf, entry1Certificate, entry1Key)
		entry2, err := store.CreateCertificate(kpf.Name()+"-2", lcf2)
		require.NoError(t, err)
		require.NotNil(t, entry2)
	}
}

func openStore(t *testing.T, path string) *FSStore {
	store, err := Open(path)
	require.NoError(t, err)
	require.NotNil(t, store)
	return store
}

func traverseStoreEntries(t *testing.T, store *FSStore) int {
	storeEntries := store.Entries()
	count := 0
	for {
		storeEntry := storeEntries.Next()
		if storeEntry == nil {
			break
		}
		count++
	}
	return count
}

func mkhome(t *testing.T) string {
	home, err := os.MkdirTemp("", "store*")
	require.NoError(t, err)
	return home
}

func init() {
	logging.UpdateRootLogger(logging.NewConsoleLogger(os.Stdout, false), zerolog.DebugLevel)
}
