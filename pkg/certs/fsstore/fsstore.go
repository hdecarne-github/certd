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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/internal/security"
	"github.com/hdecarne-github/certd/pkg/certs"
	"github.com/jellydator/ttlcache/v3"
	"github.com/rs/zerolog"
)

const settingsFile = ".store"
const keyExtension = ".key"
const crtExtension = ".crt"
const csrExtension = ".csr"
const crlExtension = ".crl"
const attributesExtension = ".json"

var certificateCacheOptions []ttlcache.Option[string, *x509.Certificate] = []ttlcache.Option[string, *x509.Certificate]{ttlcache.WithCapacity[string, *x509.Certificate](100)}
var certificateRequestCacheOptions []ttlcache.Option[string, *x509.CertificateRequest] = []ttlcache.Option[string, *x509.CertificateRequest]{ttlcache.WithCapacity[string, *x509.CertificateRequest](100)}
var revocationListCacheOptions []ttlcache.Option[string, *x509.RevocationList] = []ttlcache.Option[string, *x509.RevocationList]{ttlcache.WithCapacity[string, *x509.RevocationList](100)}
var attributesCacheOptions []ttlcache.Option[string, *certs.StoreEntryAttributes] = []ttlcache.Option[string, *certs.StoreEntryAttributes]{ttlcache.WithCapacity[string, *certs.StoreEntryAttributes](100)}

const storeDirPerm = 0700
const storeFilePerm = 0600

type FSStore struct {
	name                    string
	path                    string
	secret                  *security.Secret
	entries                 []string
	certificateCache        *ttlcache.Cache[string, *x509.Certificate]
	certificateRequestCache *ttlcache.Cache[string, *x509.CertificateRequest]
	revocationListCache     *ttlcache.Cache[string, *x509.RevocationList]
	attributesCache         *ttlcache.Cache[string, *certs.StoreEntryAttributes]
	lock                    sync.RWMutex
	logger                  *zerolog.Logger
}

type fsStoreSettings struct {
	Secret string `json:"secret"`
}

func Init(path string) (*FSStore, error) {
	return newFSStore(path, true)
}

func Open(path string) (*FSStore, error) {
	return newFSStore(path, false)
}

func newFSStore(path string, init bool) (*FSStore, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to determine absolute path for '%s' (cause: %w)", path, err)
	}
	name := "fs:" + absPath
	logger := logging.RootLogger().With().Str("store", name).Logger()
	if init {
		logger.Info().Msg("Creating FS certificate store")
		err := initFSStore(path)
		if err != nil {
			return nil, err
		}
	}
	logger.Info().Msg("Opening FS certificate store")
	settings, err := loadFSStoreSettings(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load FS certificate store (cause: %w)", err)
	}
	secret, err := security.Wrap(settings.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap secret (cause: %w)", err)
	}
	store := &FSStore{
		name:                    name,
		path:                    absPath,
		secret:                  secret,
		entries:                 make([]string, 0),
		certificateCache:        ttlcache.New(certificateCacheOptions...),
		certificateRequestCache: ttlcache.New(certificateRequestCacheOptions...),
		revocationListCache:     ttlcache.New(revocationListCacheOptions...),
		attributesCache:         ttlcache.New(attributesCacheOptions...),
		logger:                  &logger,
	}
	err = store.scan()
	if err != nil {
		return nil, err
	}
	return store, nil
}

func initFSStore(path string) error {
	settings := &fsStoreSettings{}
	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return fmt.Errorf("failed to generate random secret (cause: %w)", err)
	}
	settings.Secret = base64.StdEncoding.EncodeToString(secretBytes)
	return writeFSStoreSettings(path, settings)
}

func writeFSStoreSettings(path string, settings *fsStoreSettings) error {
	settingsBytes, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal store settings (cause: %w)", err)
	}
	err = os.Mkdir(path, storeDirPerm)
	if err != nil {
		return fmt.Errorf("failed to create store directory '%s' (cause: %w)", path, err)
	}
	file := filepath.Join(path, settingsFile)
	err = os.WriteFile(file, settingsBytes, storeFilePerm)
	if err != nil {
		return fmt.Errorf("failed to write store settings file '%s' (cause: %w)", file, err)
	}
	return nil
}

func loadFSStoreSettings(path string) (*fsStoreSettings, error) {
	file := filepath.Join(path, settingsFile)
	settingsBytes, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read store settings file '%s' (cause: %w)", file, err)
	}
	settings := &fsStoreSettings{}
	err = json.Unmarshal(settingsBytes, settings)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal store settings (cause: %w)", err)
	}
	return settings, nil
}

func (store *FSStore) Name() string {
	return store.name
}

func (store *FSStore) Entries() certs.StoreEntries {
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

func (storeEntries *fsStoreEntries) Next() certs.StoreEntry {
	if storeEntries.next >= len(storeEntries.entries) {
		return nil
	}
	storeEntry := storeEntries.store.newFSStoreEntry(storeEntries.entries[storeEntries.next])
	storeEntries.next++
	return storeEntry
}

func (store *FSStore) Entry(name string) (certs.StoreEntry, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()
	exists := store.hasAttributes(name)
	if !exists {
		return nil, fs.ErrNotExist
	}
	return store.newFSStoreEntry(name), nil
}

func (store *FSStore) CreateCertificate(name string, factory certs.CertificateFactory) (certs.StoreEntry, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	files := store.newFileGroup(name, keyExtension, crtExtension, attributesExtension)
	defer files.close()
	keyFile, err := files.create(keyExtension)
	if err != nil {
		return nil, err
	}
	crtFile, err := files.create(crtExtension)
	if err != nil {
		return nil, err
	}
	attributesFiles, err := files.create(attributesExtension)
	if err != nil {
		return nil, err
	}
	attributes := &certs.StoreEntryAttributes{
		Provider: factory.Name(),
	}
	key, certificate, err := factory.New()
	if err != nil {
		return nil, err
	}
	err = store.writeKey(name, keyFile, key)
	if err != nil {
		return nil, err
	}
	err = store.writeCertificate(name, crtFile, certificate)
	if err != nil {
		return nil, err
	}
	err = store.writeAttributes(name, attributesFiles, attributes)
	if err != nil {
		return nil, err
	}
	files.keep()
	store.entries = append(store.entries, name)
	sort.Strings(store.entries)
	return store.newFSStoreEntry(name), nil
}

func (store *FSStore) CreateCertificateRequest(name string, factory certs.CertificateRequestFactory) (certs.StoreEntry, error) {
	store.lock.Lock()
	defer store.lock.Unlock()
	files := store.newFileGroup(name, keyExtension, csrExtension, attributesExtension)
	defer files.close()
	keyFile, err := files.create(keyExtension)
	if err != nil {
		return nil, err
	}
	csrFile, err := files.create(csrExtension)
	if err != nil {
		return nil, err
	}
	attributesFiles, err := files.create(attributesExtension)
	if err != nil {
		return nil, err
	}
	attributes := &certs.StoreEntryAttributes{
		Provider: factory.Name(),
	}
	key, certificateRequest, err := factory.New()
	if err != nil {
		return nil, err
	}
	err = store.writeKey(name, keyFile, key)
	if err != nil {
		return nil, err
	}
	err = store.writeCertificateRequest(name, csrFile, certificateRequest)
	if err != nil {
		return nil, err
	}
	err = store.writeAttributes(name, attributesFiles, attributes)
	if err != nil {
		return nil, err
	}
	files.keep()
	store.entries = append(store.entries, name)
	sort.Strings(store.entries)
	return store.newFSStoreEntry(name), nil
}

func (store *FSStore) scan() error {
	store.logger.Info().Msg("Scanning...")
	pathInfo, err := os.Stat(store.path)
	if err != nil {
		return fmt.Errorf("failed to stat store path '%s' (cause: %w)", store.path, err)
	}
	if !pathInfo.IsDir() {
		return fmt.Errorf("store path '%s' is not a directory", store.path)
	}
	pathPerm := pathInfo.Mode().Perm()
	if (pathPerm | storeDirPerm) != storeDirPerm {
		store.logger.Warn().Msgf("Insecure permissions store path permissions %s", pathInfo.Mode())
	}
	err = fs.WalkDir(os.DirFS(store.path), ".", store.scanPath)
	if err != nil {
		return fmt.Errorf("failed to scan store path '%s' (cause: %w)", store.path, err)
	}
	return nil
}

func (store *FSStore) scanPath(current string, d fs.DirEntry, err error) error {
	if current == "." || current == settingsFile {
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
	last := len(store.entries) - 1
	if last < 0 || store.entries[last] != storeEntryName {
		if store.validateStoreEntry(storeEntryName) {
			store.logger.Debug().Msgf("Adding store entry '%s'", storeEntryName)
			store.entries = append(store.entries, storeEntryName)
		} else {
			store.logger.Warn().Msgf("Ignoring unrelated file '%s'", current)
		}
	}
	return err
}

func (store *FSStore) validateStoreEntry(name string) bool {
	hasKey := store.hasKey(name)
	hasCertificate := store.hasCertificate(name)
	hasCertificateRequest := store.hasCertificateRequest(name)
	hasAttributes := store.hasAttributes(name)
	return hasAttributes && (hasCertificate || (hasKey && hasCertificateRequest))
}

func (store *FSStore) writeKey(name string, file *os.File, key crypto.PrivateKey) error {
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

func (store *FSStore) hasKey(name string) bool {
	keyFilePath := filepath.Join(store.path, name+keyExtension)
	_, err := os.Stat(keyFilePath)
	return err == nil
}

func (store *FSStore) readKey(name string) (crypto.PrivateKey, error) {
	keyFilePath := filepath.Join(store.path, name+keyExtension)
	store.logger.Info().Msgf("Reading key file '%s'...", keyFilePath)
	keyFileBytes, err := os.ReadFile(keyFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
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

func (store *FSStore) writeCertificate(name string, file *os.File, certificate *x509.Certificate) error {
	store.logger.Info().Msgf("Writing certificate file '%s'...", file.Name())
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Raw,
	}
	err := pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode or write certificate (cause: %w)", err)
	}
	store.certificateCache.Set(name, certificate, ttlcache.NoTTL)
	return nil
}

func (store *FSStore) hasCertificate(name string) bool {
	crtFilePath := filepath.Join(store.path, name+crtExtension)
	_, err := os.Stat(crtFilePath)
	return err == nil
}

func (store *FSStore) readCertificate(name string) (*x509.Certificate, error) {
	crtFilePath := filepath.Join(store.path, name+crtExtension)
	cached := store.certificateCache.Get(name)
	if cached != nil {
		store.logger.Debug().Msgf("Using cached certificate file '%s'...", crtFilePath)
		return cached.Value(), nil
	}
	store.logger.Info().Msgf("Reading certificate file '%s'...", crtFilePath)
	crtFileBytes, err := os.ReadFile(crtFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
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
	store.certificateCache.Set(name, certificate, ttlcache.NoTTL)
	return certificate, nil
}

func (store *FSStore) writeCertificateRequest(name string, file *os.File, certificateRequest *x509.CertificateRequest) error {
	store.logger.Info().Msgf("Writing certificate request file '%s'...", file.Name())
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: certificateRequest.Raw,
	}
	err := pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode or write certificate request (cause: %w)", err)
	}
	store.certificateRequestCache.Set(name, certificateRequest, ttlcache.NoTTL)
	return nil
}

func (store *FSStore) hasCertificateRequest(name string) bool {
	csrFilePath := filepath.Join(store.path, name+csrExtension)
	_, err := os.Stat(csrFilePath)
	return err == nil
}

func (store *FSStore) readCertificateRequest(name string) (*x509.CertificateRequest, error) {
	csrFilePath := filepath.Join(store.path, name+csrExtension)
	cached := store.certificateRequestCache.Get(name)
	if cached != nil {
		store.logger.Debug().Msgf("Using cached certificate request file '%s'...", csrFilePath)
		return cached.Value(), nil
	}
	store.logger.Info().Msgf("Reading certificate request file '%s'...", csrFilePath)
	csrFileBytes, err := os.ReadFile(csrFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read certificate request file '%s' (cause: %w)", csrFilePath, err)
	}
	pemBlock, rest := pem.Decode(csrFileBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate request file '%s'", csrFilePath)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in certificate request file '%s'", csrFilePath)
	}
	certificateRequest, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request from file '%s' (cause: %w)", csrFilePath, err)
	}
	store.certificateRequestCache.Set(name, certificateRequest, ttlcache.NoTTL)
	return certificateRequest, nil
}

func (store *FSStore) writeRevocationList(name string, file *os.File, revocationList *x509.RevocationList) error {
	store.logger.Info().Msgf("Writing revocation list file '%s'...", file.Name())
	pemBlock := &pem.Block{
		Type:  "X509 CRL",
		Bytes: revocationList.Raw,
	}
	err := pem.Encode(file, pemBlock)
	if err != nil {
		return fmt.Errorf("failed to encode or write revocation list (cause: %w)", err)
	}
	store.revocationListCache.Set(name, revocationList, ttlcache.NoTTL)
	return nil
}

func (store *FSStore) hasRevocationList(name string) bool {
	crlFilePath := filepath.Join(store.path, name+crlExtension)
	_, err := os.Stat(crlFilePath)
	return err == nil
}

func (store *FSStore) readRevocationList(name string) (*x509.RevocationList, error) {
	crlFilePath := filepath.Join(store.path, name+crlExtension)
	cached := store.revocationListCache.Get(name)
	if cached != nil {
		store.logger.Debug().Msgf("Using cached revocation list file '%s'...", crlFilePath)
		return cached.Value(), nil
	}
	store.logger.Info().Msgf("Reading revocation list file '%s'...", crlFilePath)
	crlFileBytes, err := os.ReadFile(crlFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read revocation list file '%s' (cause: %w)", crlFilePath, err)
	}
	pemBlock, rest := pem.Decode(crlFileBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode revocation list file '%s'", crlFilePath)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in revocation list file '%s'", crlFilePath)
	}
	revocationList, err := x509.ParseRevocationList(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse revocation list from file '%s' (cause: %w)", crlFilePath, err)
	}
	store.revocationListCache.Set(name, revocationList, ttlcache.NoTTL)
	return revocationList, nil
}

func (store *FSStore) writeAttributes(name string, file *os.File, attributes *certs.StoreEntryAttributes) error {
	store.logger.Info().Msgf("Writing attributes file '%s'...", file.Name())
	attributeBytes, err := json.MarshalIndent(attributes, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attributes (cause: %w)", err)
	}
	_, err = file.Write(attributeBytes)
	if err != nil {
		return fmt.Errorf("failed to write attributes file '%s' (cause: %w)", file.Name(), err)
	}
	store.attributesCache.Set(name, attributes, ttlcache.NoTTL)
	return nil
}

func (store *FSStore) hasAttributes(name string) bool {
	attributesFilePath := filepath.Join(store.path, name+attributesExtension)
	_, err := os.Stat(attributesFilePath)
	return err == nil
}

func (store *FSStore) readAttributes(name string) (*certs.StoreEntryAttributes, error) {
	attributesFilePath := filepath.Join(store.path, name+attributesExtension)
	cached := store.attributesCache.Get(name)
	if cached != nil {
		store.logger.Debug().Msgf("Using cached attributes file '%s'...", attributesFilePath)
		return cached.Value(), nil
	}
	store.logger.Info().Msgf("Reading attributes file '%s'...", attributesFilePath)
	attributesBytes, err := os.ReadFile(attributesFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read attributes file '%s' (cause: %w)", attributesFilePath, err)
	}
	attributes := &certs.StoreEntryAttributes{}
	err = json.Unmarshal(attributesBytes, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes from file '%s' (cause: %w)", attributesFilePath, err)
	}
	store.attributesCache.Set(name, attributes, ttlcache.NoTTL)
	return attributes, nil
}

func (store *FSStore) newFSStoreEntry(name string) certs.StoreEntry {
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

func (storeEntry *fsStoreEntry) Store() certs.Store {
	return storeEntry.store
}

func (storeEntry *fsStoreEntry) HasKey() bool {
	return storeEntry.store.hasKey(storeEntry.name)
}

func (storeEntry *fsStoreEntry) Key() (crypto.PrivateKey, error) {
	return storeEntry.store.readKey(storeEntry.name)
}

func (storeEntry *fsStoreEntry) HasCertificate() bool {
	return storeEntry.store.hasCertificate(storeEntry.name)
}

func (storeEntry *fsStoreEntry) Certificate() (*x509.Certificate, error) {
	return storeEntry.store.readCertificate(storeEntry.name)
}

func (storeEntry *fsStoreEntry) HasCertificateRequest() bool {
	return storeEntry.store.hasCertificateRequest(storeEntry.name)
}

func (storeEntry *fsStoreEntry) CertificateRequest() (*x509.CertificateRequest, error) {
	return storeEntry.store.readCertificateRequest(storeEntry.name)
}

func (storeEntry *fsStoreEntry) HasRevocationList() bool {
	return storeEntry.store.hasRevocationList(storeEntry.name)
}

func (storeEntry *fsStoreEntry) RevocationList() (*x509.RevocationList, error) {
	return storeEntry.store.readRevocationList(storeEntry.name)
}

func (storeEntry *fsStoreEntry) Attributes() (*certs.StoreEntryAttributes, error) {
	return storeEntry.store.readAttributes(storeEntry.name)
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

func (fg *fileGroup) create(extension string) (*os.File, error) {
	for filePath, file := range fg.files {
		if strings.HasSuffix(filePath, extension) {
			if file != nil {
				return file, nil
			}
			newFile, err := os.OpenFile(filePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, storeFilePerm)
			if err != nil {
				return nil, fmt.Errorf("failed to create file '%s' (cause: %w)", filePath, err)
			}
			fg.files[filePath] = newFile
			return newFile, nil
		}
	}
	return nil, fmt.Errorf("%s file not part of file group", extension)
}

func (fg *fileGroup) keep() {
	fg.release = false
}

func (fg *fileGroup) close() {
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
