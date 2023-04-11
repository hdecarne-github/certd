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

package server

import (
	"crypto"
	cryptoecdsa "crypto/ecdsa"
	cryptoed25519 "crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	cryptorsa "crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hdecarne-github/certd/internal/config"
	"github.com/hdecarne-github/certd/pkg/certs"
	"github.com/hdecarne-github/certd/pkg/certs/acme"
	x509ext "github.com/hdecarne-github/certd/pkg/certs/extensions"
	"github.com/hdecarne-github/certd/pkg/certs/local"
	"github.com/hdecarne-github/certd/pkg/certs/remote"
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/hdecarne-github/certd/pkg/keys/ecdsa"
	"github.com/hdecarne-github/certd/pkg/keys/ed25519"
	"github.com/hdecarne-github/certd/pkg/keys/rsa"
)

const errorInvalidRequest = "Invalid reqest"
const errorInvalidKeyType = "Invalid key type"
const errorInvalidIssuer = "Invalid issuer"
const errorInvalidDN = "Invalid Distinguished Name"
const errorInvalidACMECA = "Invalid ACME CA"
const errorGenerateFailure = "Certificate generation failed"
const errorEntryNotFound = "Unknown store entry"

func (s *server) storeEntries(c *gin.Context) {
	entries := make([]StoreEntryResponse, 0)
	storeEntries := s.store.Entries()
	for {
		storeEntry := storeEntries.Next()
		if storeEntry == nil {
			break
		}
		storeEntryResponse, err := s.newStoreEntryResponse(storeEntry)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		entries = append(entries, *storeEntryResponse)
	}
	response := &StoreEntriesResponse{Entries: entries}
	c.JSON(http.StatusOK, response)
}

func (s *server) newStoreEntryResponse(storeEntry certs.StoreEntry) (*StoreEntryResponse, error) {
	hasKey := storeEntry.HasKey()
	hasCertificate := storeEntry.HasCertificate()
	hasCertificateRequest := storeEntry.HasCertificateRequest()
	hasRevocationList := storeEntry.HasRevocationList()
	var dn string
	var ca bool
	var validFrom time.Time
	var validTo time.Time
	if hasCertificate {
		certificate, err := storeEntry.Certificate()
		if err != nil {
			return nil, err
		}
		dn = certificate.Subject.String()
		ca = certificate.IsCA
		validFrom = certificate.NotBefore
		validTo = certificate.NotAfter
	} else if hasCertificateRequest {
		certificateRequest, err := storeEntry.CertificateRequest()
		if err != nil {
			return nil, err
		}
		dn = certificateRequest.Subject.String()
		ca = false
		validFrom = time.UnixMilli(0)
		validTo = validFrom
	} else {
		// should never happen
		return nil, fmt.Errorf("invalid store entry '%s'", storeEntry.Name())
	}
	storeEntryResponse := &StoreEntryResponse{
		Name:      storeEntry.Name(),
		DN:        dn,
		Key:       hasKey,
		CRT:       hasCertificate,
		CSR:       hasCertificateRequest,
		CRL:       hasRevocationList,
		CA:        ca,
		ValidFrom: validFrom,
		ValidTo:   validTo,
	}
	return storeEntryResponse, nil
}

func (s *server) storeEntryDetails(c *gin.Context) {
	name := c.Param("name")
	storeEntry, err := s.store.Entry(name)
	if errors.Is(err, fs.ErrNotExist) {
		c.AbortWithStatusJSON(http.StatusNotFound, &ServerErrorResponse{Message: errorEntryNotFound})
		return
	} else if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	storeEntryResponse, err := s.newStoreEntryResponse(storeEntry)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	crtDetails := StoreEntryCRTDetailsResponse{Extensions: make([][2]string, 0)}
	if storeEntryResponse.CRT {
		certificate, err := storeEntry.Certificate()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		crtDetails.Version = certificate.Version
		crtDetails.Serial = "0x" + certificate.SerialNumber.Text(16)
		crtDetails.KeyType = s.getKeyType(certificate.PublicKey)
		crtDetails.Issuer = certificate.Issuer.String()
		crtDetails.SigAlg = certificate.SignatureAlgorithm.String()
		crtDetails.Extensions = s.appendExtensionDetails(crtDetails.Extensions, certificate)
	}
	response := &StoreEntryDetailsResponse{
		StoreEntryResponse: *storeEntryResponse,
		CRTDetails:         crtDetails,
	}
	c.JSON(http.StatusOK, response)
}

func (s *server) appendExtensionDetails(extensions [][2]string, certificate *x509.Certificate) [][2]string {
	for _, rawExtension := range certificate.Extensions {
		rawExtensionId := rawExtension.Id.String()
		switch rawExtensionId {
		case x509ext.BasicConstraintsExtensionOID:
			extensions = append(extensions, [2]string{x509ext.BasicConstraintsExtensionName,
				x509ext.BasicConstraintsString(certificate.IsCA, certificate.MaxPathLen, certificate.MaxPathLenZero)})
		case x509ext.SubjectKeyIdentifierExtensionOID:
			extensions = append(extensions, [2]string{x509ext.SubjectKeyIdentifierExtensionName,
				x509ext.KeyIdentifierString(certificate.SubjectKeyId)})
		case x509ext.AuthorityKeyIdentifierExtensionOID:
			extensions = append(extensions, [2]string{x509ext.AuthorityKeyIdentifierExtensionName,
				x509ext.KeyIdentifierString(certificate.AuthorityKeyId)})
		case x509ext.KeyUsageExtensionOID:
			extensions = append(extensions, [2]string{x509ext.KeyUsageExtensionName,
				x509ext.KeyUsageString(certificate.KeyUsage)})
		case x509ext.ExtKeyUsageExtensionOID:
			extensions = append(extensions, [2]string{x509ext.ExtKeyUsageExtensionName,
				x509ext.ExtKeyUsageString(certificate.ExtKeyUsage, certificate.UnknownExtKeyUsage)})
		default:
			extensions = append(extensions, [2]string{rawExtensionId, ""})
		}
	}
	sort.Slice(extensions, func(i, j int) bool {
		return strings.Compare(extensions[i][0], extensions[j][0]) < 0
	})
	return extensions
}

func (s *server) storeCAs(c *gin.Context) {
	cas := make([]StoreCAResponse, 0)
	localCA := StoreCAResponse{
		Name: local.ProviderName,
	}
	cas = append(cas, localCA)
	remoteCA := StoreCAResponse{
		Name: remote.ProviderName,
	}
	cas = append(cas, remoteCA)
	acmeConfig, err := acme.Load(config.ResolveConfigPath(s.config.BasePath, s.config.ACMEConfig))
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	for _, acmeProvider := range acmeConfig.Providers {
		acmeCA := StoreCAResponse{
			Name: acme.ProviderPrefix + acmeProvider.Name,
		}
		cas = append(cas, acmeCA)
	}
	response := &StoreCAsResponse{
		CAs: cas,
	}
	c.JSON(http.StatusOK, response)
}

func (s *server) storeLocalIssuers(c *gin.Context) {
	issuers := make([]StoreLocalIssuerResponse, 0)
	storeEntries := s.store.Entries()
	for {
		storeEntry := storeEntries.Next()
		if storeEntry == nil {
			break
		}
		certificate, err := storeEntry.Certificate()
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if certificate != nil && certificate.IsCA && storeEntry.HasKey() {
			issuer := StoreLocalIssuerResponse{
				Name: storeEntry.Name(),
			}
			issuers = append(issuers, issuer)
		}
	}
	response := &StoreLocalIssuersResponse{
		Issuers: issuers,
	}
	c.JSON(http.StatusOK, response)
}

func (s *server) storeLocalGenerate(c *gin.Context) {
	generateLocal := &StoreGenerateLocalRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(generateLocal)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidRequest})
		return
	}
	keyFactory, err := s.getKeyFactory(generateLocal.KeyType)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidKeyType})
		return
	}
	issuer := generateLocal.Issuer
	var parent *x509.Certificate
	var signer crypto.PrivateKey
	if issuer != "" {
		parent, signer, err = s.resolveIssuer(issuer)
		if err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if parent == nil || signer == nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidIssuer})
			return
		}
	}
	dn, err := certs.ParseDN(generateLocal.DN)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidDN})
		return
	}
	serialNumber, err := s.generateSerialNumber()
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	template := &x509.Certificate{
		Version:      3,
		SerialNumber: serialNumber,
		Subject:      *dn,
		NotBefore:    generateLocal.ValidFrom,
		NotAfter:     generateLocal.ValidTo,
	}
	template.KeyUsage = generateLocal.KeyUsage.toKeyUsage()
	template.ExtKeyUsage = generateLocal.ExtKeyUsage.toExtKeyUsage()
	generateLocal.BasicConstraint.applyToCertificate(template)
	localFactory := local.NewLocalCertificateFactory(template, keyFactory, parent, signer)
	_, err = s.store.CreateCertificate(generateLocal.Name, localFactory)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, &ServerErrorResponse{Message: errorGenerateFailure})
		return
	}
	c.Status(http.StatusOK)
}

func (s *server) resolveIssuer(issuer string) (*x509.Certificate, crypto.PrivateKey, error) {
	issuerStoreEntry, err := s.store.Entry(issuer)
	if err != nil {
		return nil, nil, nil
	}
	parent, err := issuerStoreEntry.Certificate()
	if err != nil || parent == nil {
		return nil, nil, err
	}
	signer, err := issuerStoreEntry.Key()
	if err != nil || signer == nil {
		return nil, nil, err
	}
	return parent, signer, nil
}

func (s *server) storeRemoteGenerate(c *gin.Context) {
	generateRemote := &StoreGenerateRemoteRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(generateRemote)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidRequest})
	}
	keyFactory, err := s.getKeyFactory(generateRemote.KeyType)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidKeyType})
		return
	}
	dn, err := certs.ParseDN(generateRemote.DN)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidDN})
		return
	}
	template := &x509.CertificateRequest{
		Version: 3,
		Subject: *dn,
	}
	remoteFactory := remote.NewLocalCertificateRequestFactory(template, keyFactory)
	_, err = s.store.CreateCertificateRequest(generateRemote.Name, remoteFactory)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, &ServerErrorResponse{Message: errorGenerateFailure})
		return
	}
	c.Status(http.StatusOK)
}

func (s *server) storeACMEGenerate(c *gin.Context) {
	generateACME := &StoreGenerateACMERequest{}
	err := json.NewDecoder(c.Request.Body).Decode(generateACME)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidRequest})
	}
	keyFactory, err := s.getKeyFactory(generateACME.KeyType)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidKeyType})
		return
	}
	acmeConfigPath := config.ResolveConfigPath(s.config.BasePath, s.config.ACMEConfig)
	acmeProvider, err := s.getACMEProvider(generateACME.CA)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, &ServerErrorResponse{Message: errorInvalidACMECA})
		return
	}
	acmeFactory := acme.NewACMECertificateFactory(generateACME.Domains, acmeConfigPath, acmeProvider, keyFactory)
	_, err = s.store.CreateCertificate(generateACME.Name, acmeFactory)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotFound, &ServerErrorResponse{Message: errorGenerateFailure})
		return
	}
	c.Status(http.StatusOK)
}

func (s *server) generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number (cause: %w)", err)
	}
	return serial, nil
}

func (s *server) getKeyFactory(keyType string) (keys.KeyPairFactory, error) {
	switch keyType {
	case "ECDSA P-224":
		return ecdsa.NewECDSAKeyPairFactory(elliptic.P224()), nil
	case "ECDSA P-256":
		return ecdsa.NewECDSAKeyPairFactory(elliptic.P256()), nil
	case "ECDSA P-384":
		return ecdsa.NewECDSAKeyPairFactory(elliptic.P384()), nil
	case "ECDSA P-521":
		return ecdsa.NewECDSAKeyPairFactory(elliptic.P521()), nil
	case "ED25519":
		return ed25519.NewED25519KeyPairFactory(), nil
	case "RSA 2048":
		return rsa.NewRSAKeyPairFactory(2048), nil
	case "RSA 3072":
		return rsa.NewRSAKeyPairFactory(3072), nil
	case "RSA 4096":
		return rsa.NewRSAKeyPairFactory(4092), nil
	}
	return nil, fmt.Errorf("unrecognized key type '%s'", keyType)
}

func (s *server) getKeyType(publicKey any) string {
	ecdsaPublicKey, ok := publicKey.(*cryptoecdsa.PublicKey)
	if ok {
		return fmt.Sprintf("ECSDA P-%d", ecdsaPublicKey.Curve.Params().BitSize)
	}
	_, ok = publicKey.(cryptoed25519.PublicKey)
	if ok {
		return "ED25519"
	}
	rsaPublicKey, ok := publicKey.(*cryptorsa.PublicKey)
	if ok {
		return fmt.Sprintf("RSA %d", rsaPublicKey.N.BitLen())
	}
	return "<unrecognized>"
}

func (s *server) getACMEProvider(ca string) (string, error) {
	if !strings.HasPrefix(ca, acme.ProviderPrefix) {
		return "", fmt.Errorf("unrecognized ACME CA '%s'", ca)
	}
	return string([]rune(ca)[len([]rune(acme.ProviderPrefix)):]), nil
}
