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

package acme

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/pkg/certs"
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/rs/zerolog"
)

const ProviderPrefix = "ACME:"

type ACMECertificateFactory struct {
	name         string
	domains      []string
	configPath   string
	providerName string
	keyFactory   keys.KeyPairFactory
	logger       *zerolog.Logger
}

func NewACMECertificateFactory(domains []string, configPath string, providerName string, keyFactory keys.KeyPairFactory) certs.CertificateFactory {
	name := ProviderPrefix + providerName
	logger := logging.RootLogger().With().Str("Provider", name).Logger()
	return &ACMECertificateFactory{
		name:         name,
		domains:      domains,
		configPath:   configPath,
		providerName: providerName,
		keyFactory:   keyFactory,
		logger:       &logger,
	}
}

func (factory *ACMECertificateFactory) Name() string {
	return factory.name
}

func (factory *ACMECertificateFactory) New() (crypto.PrivateKey, *x509.Certificate, error) {
	provider, domainConfig, err := factory.evalConfig()
	if err != nil {
		return nil, nil, err
	}
	registration, err := getRegistration(provider, factory.keyFactory)
	if err != nil {
		return nil, nil, err
	}
	config := lego.NewConfig(registration)
	config.CADirURL = provider.URL
	keyType, err := factory.keyType()
	if err != nil {
		return nil, nil, err
	}
	config.Certificate.KeyType = keyType
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client for provider '%s' (cause: %w)", factory.name, err)
	}
	if !registration.isValid(client) {
		err = registration.refresh(client, factory.keyFactory)
		if err != nil {
			return nil, nil, err
		}
	}
	if domainConfig.Http01Challenge.Enabled {
		client.Challenge.SetHTTP01Provider(http01.NewProviderServer(domainConfig.Http01Challenge.Iface, strconv.Itoa(domainConfig.Http01Challenge.Port)))
	}
	if domainConfig.TLSAPN01Challenge.Enabled {
		client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer(domainConfig.TLSAPN01Challenge.Iface, strconv.Itoa(domainConfig.TLSAPN01Challenge.Port)))
	}
	key, err := factory.keyFactory.New()
	if err != nil {
		return nil, nil, err
	}
	request := certificate.ObtainRequest{
		Domains:    factory.domains,
		PrivateKey: key.Private(),
		Bundle:     false,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, nil, err
	}
	obtainedKey, err := factory.decodePrivateKey(certificates.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	obtainedCertificate, err := factory.decodeCertificate(certificates.Certificate)
	if err != nil {
		return nil, nil, err
	}
	return obtainedKey, obtainedCertificate, nil
}

func (factory *ACMECertificateFactory) decodePrivateKey(keyBytes []byte) (crypto.PrivateKey, error) {
	pemBlock, rest := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode key")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in key")
	}
	var key crypto.PrivateKey
	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key (cause: %w)", err)
		}
		key = ecKey
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key (cause: %w)", err)
		}
		key = rsaKey
	default:
		return nil, fmt.Errorf("unexpected PEM block type '%s'", pemBlock.Type)
	}
	return key, nil
}

func (factory *ACMECertificateFactory) decodeCertificate(certificateBytes []byte) (*x509.Certificate, error) {
	pemBlock, rest := pem.Decode(certificateBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("failed to decode certificate")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing bytes in certificate")
	}
	certificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (cause: %w)", err)
	}
	return certificate, nil
}

func (factory *ACMECertificateFactory) evalConfig() (*Provider, *DomainConfig, error) {
	config, err := Load(factory.configPath)
	if err != nil {
		return nil, nil, err
	}
	var provider *Provider
	for _, configProvider := range config.Providers {
		if configProvider.Name == factory.providerName {
			provider = &configProvider
			break
		}
	}
	if provider == nil {
		return nil, nil, fmt.Errorf("unknown ACME provider '%s'", factory.providerName)
	}
	if len(factory.domains) == 0 {
		return nil, nil, fmt.Errorf("missing domain information")
	}
	domain := factory.domains[0] + "."
	var domainConfig *DomainConfig
	for _, configDomainConfig := range config.Domains {
		if strings.HasSuffix(domain, configDomainConfig.Domain) {
			if domainConfig == nil || len(domainConfig.Domain) < len(configDomainConfig.Domain) {
				domainConfig = &configDomainConfig
			}
		}
	}
	if domainConfig == nil {
		return nil, nil, fmt.Errorf("missing Domain configuration for domain '%s'", domain)
	}
	return provider, domainConfig, nil
}

func (factory *ACMECertificateFactory) keyType() (certcrypto.KeyType, error) {
	keyProvider := factory.keyFactory.Name()
	switch keyProvider {
	case "ECDSA P-256":
		return certcrypto.EC256, nil
	case "ECDSA P-384":
		return certcrypto.EC384, nil
	case "RSA 2048":
		return certcrypto.RSA2048, nil
	case "RSA 4096":
		return certcrypto.RSA4096, nil
	case "RSA 8192":
		return certcrypto.RSA8192, nil
	}
	return "", fmt.Errorf("unsupported key provider '%s'", keyProvider)
}

func init() {

}
