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

package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/internal/security"
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/rs/zerolog"
)

const keyExtension = ".key"
const crtExtension = ".crt"
const csrExtension = ".csr"
const crlExtension = ".crl"
const attributesExtension = ".json"

const storeDirMode = 0700
const storeFileMode = 0600

type FSStore struct {
	name    string
	path    string
	secret  *security.Secret
	entries []string
	lock    sync.RWMutex
	logger  *zerolog.Logger
}

func NewFSStore(path string, secret string) (*FSStore, error) {
	return openFSStore(path, secret, true)
}

func OpenFSStore(path string, secret string) (*FSStore, error) {
	return openFSStore(path, secret, false)
}

func openFSStore(path string, secret string, mkdir bool) (*FSStore, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path for '%s' (cause: %w)", path, err)
	}
	name := "fs:" + absPath
	logger := logging.RootLogger().With().Str("store", name).Logger()
	if mkdir {
		logger.Info().Msg("Creating FS certificate store")
		err := os.Mkdir(path, storeDirMode)
		if err != nil {
			return nil, fmt.Errorf("failed to create directory '%s' (cause: %w)", path, err)
		}
	}
	logger.Info().Msg("Opening FS certificate store")
	wrappedSecret, err := security.Wrap(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap secret (cause: %w)", err)
	}
	store := &FSStore{
		name:    name,
		path:    absPath,
		secret:  wrappedSecret,
		entries: make([]string, 0),
		logger:  &logger,
	}
	err = store.scan()
	if err != nil {
		return nil, err
	}
	return store, nil
}

func (store *FSStore) Name() string {
	return store.name
}

func (store *FSStore) Entries() StoreEntries {
	store.lock.RLock()
	defer store.lock.RUnlock()
	entries := store.entries
	return &fsStoreEntries{
		store:   store,
		entries: entries,
		next:    0,
	}
}

type fsStoreEntries struct {
	store   *FSStore
	entries []string
	next    int
}

func (storeEntries *fsStoreEntries) Reset() {
	storeEntries.next = 0
}

func (storeEntries *fsStoreEntries) Next() StoreEntry {
	if storeEntries.next >= len(storeEntries.entries) {
		return nil
	}
	storeEntry := storeEntries.store.newFSStoreEntry(storeEntries.entries[storeEntries.next])
	storeEntries.next++
	return storeEntry
}

func (store *FSStore) CreateLocalCertificate(name string, template *x509.Certificate, parent StoreEntry, keyPair keys.KeyPair) (StoreEntry, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	files := store.newFileGroup(name, keyExtension, crtExtension)
	defer files.Close()
	keyFile, err := files.Create(keyExtension)
	if err != nil {
		return nil, err
	}
	crtFile, err := files.Create(crtExtension)
	if err != nil {
		return nil, err
	}
	certificate, err := store.createAndParseLocalCertificate(template, parent, keyPair)
	if err != nil {
		return nil, err
	}
	err = store.writeKey(keyFile, keyPair.Private())
	if err != nil {
		return nil, err
	}
	err = store.writeCertificate(crtFile, certificate)
	if err != nil {
		return nil, err
	}
	files.Keep()
	return store.newFSStoreEntry(name), nil
}

func (store *FSStore) createAndParseLocalCertificate(template *x509.Certificate, parent StoreEntry, keyPair keys.KeyPair) (*x509.Certificate, error) {
	var parentCertificate *x509.Certificate
	var signingKey crypto.PrivateKey
	if parent != nil {
		var err error
		parentCertificate, err = parent.Certificate()
		if err != nil {
			return nil, err
		}
		if parentCertificate == nil {
			return nil, fmt.Errorf("invalid parent '%s'; no certificate", parent.Name())
		}
		signingKey, err = parent.PrivateKey()
		if err != nil {
			return nil, err
		}
		if signingKey == nil {
			return nil, fmt.Errorf("invalid parent '%s'; no private key", parent.Name())
		}
	} else {
		// self-signed certificate
		parentCertificate = template
		signingKey = keyPair.Private()
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, parentCertificate, keyPair.Public(), signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate (cause: %w)", err)
	}
	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parse certificate bytes (cause: %w)", err)
	}
	return certificate, nil
}

func (store *FSStore) scan() error {
	store.logger.Info().Msgf("Scanning '%s'...", store.path)
	pathInfo, err := os.Stat(store.path)
	if err != nil {
		return fmt.Errorf("failed to stat store path '%s' (cause: %w)", store.path, err)
	}
	if !pathInfo.IsDir() {
		return fmt.Errorf("store path '%s' is not a directory", store.path)
	}
	// TODO: Evaluate pathInfo.Mode
	err = fs.WalkDir(os.DirFS(store.path), ".", store.scanPath)
	if err != nil {
		return fmt.Errorf("failed to scan store path '%s' (cause: %w)", store.path, err)
	}
	return nil
}

func (store *FSStore) scanPath(current string, d fs.DirEntry, err error) error {
	if current == "." {
		return nil
	}
	if d.IsDir() {
		store.logger.Info().Msgf("Ignoring unrecognized directory '%s'", current)
		return fs.SkipDir
	}
	var storeEntryName string
	switch filepath.Ext(current) {
	case keyExtension:
		store.logger.Debug().Msgf("Found key file '%s'", current)
		storeEntryName = strings.TrimSuffix(current, keyExtension)
	case crtExtension:
		store.logger.Debug().Msgf("Found certificate file '%s'", current)
		storeEntryName = strings.TrimSuffix(current, crtExtension)
	case csrExtension:
		store.logger.Debug().Msgf("Found certificate request file '%s'", current)
		storeEntryName = strings.TrimSuffix(current, csrExtension)
	case crlExtension:
		store.logger.Debug().Msgf("Found revocation list file '%s'", current)
		storeEntryName = strings.TrimSuffix(current, crlExtension)
	case attributesExtension:
		store.logger.Debug().Msgf("Found attributes file '%s'", current)
		storeEntryName = strings.TrimSuffix(current, attributesExtension)
	default:
		store.logger.Info().Msgf("Ignoring unrecognized file '%s'", current)
		return nil
	}
	entriesLen := len(store.entries)
	if entriesLen == 0 || store.entries[entriesLen-1] != storeEntryName {
		store.logger.Debug().Msgf("Adding store entry '%s'", storeEntryName)
		store.entries = append(store.entries, storeEntryName)
	}
	return err
}

func (store *FSStore) writeKey(file *os.File, key crypto.PrivateKey) error {
	store.logger.Info().Msgf("Writing key file '%s'...", file.Name())
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	pemBlock, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyBytes, store.secret.UnwrapBytes(), x509.PEMCipherAES256)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key (cause: %w)", err)
	}
	err = pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode or write private key (cause: %w)", err)
	}
	return nil
}

func (store *FSStore) readKey(name string) (crypto.PrivateKey, error) {
	keyFilePath := filepath.Join(store.path, name+keyExtension)
	store.logger.Info().Msgf("Reading key file '%s'...", keyFilePath)
	keyFileBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read key file '%s' (cause: %w)", keyFilePath, err)
	}
	pemBlock, rest := pem.Decode(keyFileBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode key file '%s'", keyFilePath)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in key file '%s'", keyFilePath)
	}
	keyBytes, err := x509.DecryptPEMBlock(pemBlock, store.secret.UnwrapBytes())
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key from file '%s' (cause: %w)", keyFilePath, err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key from file '%s' (cause: %w)", keyFilePath, err)
	}
	return key.(crypto.PrivateKey), nil
}

func (store *FSStore) writeCertificate(file *os.File, certificate *x509.Certificate) error {
	store.logger.Info().Msgf("Writing certificate file '%s'...", file.Name())
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}
	err := pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode or write certificate (cause: %w)", err)
	}
	return nil
}

func (store *FSStore) readCertificate(name string) (*x509.Certificate, error) {
	crtFilePath := filepath.Join(store.path, name+crtExtension)
	store.logger.Info().Msgf("Reading certificate file '%s'...", crtFilePath)
	crtFileBytes, err := os.ReadFile(crtFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read certificate file '%s' (cause: %w)", crtFilePath, err)
	}
	pemBlock, rest := pem.Decode(crtFileBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate file '%s'", crtFilePath)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in certificate file '%s'", crtFilePath)
	}
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from file '%s' (cause: %w)", crtFilePath, err)
	}
	return certificate, nil
}

func (store *FSStore) newFSStoreEntry(name string) StoreEntry {
	return &fsStoreEntry{
		name:  name,
		store: store,
	}
}

type fsStoreEntry struct {
	name  string
	store *FSStore
}

func (storeEntry *fsStoreEntry) Name() string {
	return storeEntry.name
}

func (storeEntry *fsStoreEntry) Store() Store {
	return storeEntry.store
}

func (storeEntry *fsStoreEntry) PrivateKey() (crypto.PrivateKey, error) {
	return storeEntry.store.readKey(storeEntry.name)
}

func (storeEntry *fsStoreEntry) Certificate() (*x509.Certificate, error) {
	return storeEntry.store.readCertificate(storeEntry.name)
}

func (store *FSStore) newFileGroup(name string, extensions ...string) *fileGroup {
	files := make(map[string]*os.File, len(extensions))
	for _, extension := range extensions {
		file := filepath.Join(store.path, name+extension)
		files[file] = nil
	}
	return &fileGroup{
		files:   files,
		release: true,
		logger:  store.logger,
	}
}

type fileGroup struct {
	files   map[string]*os.File
	release bool
	logger  *zerolog.Logger
}

func (fg *fileGroup) Create(extension string) (*os.File, error) {
	for filePath, file := range fg.files {
		if strings.HasSuffix(filePath, extension) {
			if file != nil {
				return file, nil
			}
			newFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, storeFileMode)
			if err != nil {
				return nil, fmt.Errorf("failed to create file '%s' (cause: %w)", filePath, err)
			}
			fg.files[filePath] = newFile
			return newFile, nil
		}
	}
	return nil, fmt.Errorf("%s file not part of file group", extension)
}

func (fg *fileGroup) Keep() {
	fg.release = false
}

func (fg *fileGroup) Close() {
	for filePath, file := range fg.files {
		if file != nil {
			err := file.Close()
			if err != nil {
				fg.logger.Warn().Msgf("Failed to close file '%s' (cause: %v)", filePath, err)
			}
			if fg.release {
				fg.logger.Debug().Msgf("Removing uncommited file '%s'...", filePath)
				err := os.Remove(filePath)
				if err != nil {
					fg.logger.Warn().Msgf("Failed to remove uncommited file '%s' (cause: %v)", filePath, err)
				}
			}
		}
	}
}
