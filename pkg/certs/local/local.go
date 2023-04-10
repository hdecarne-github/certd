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

package local

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/pkg/certs"
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/rs/zerolog"
)

const ProviderName = "Local"

type LocalCertificateFactory struct {
	template   *x509.Certificate
	keyFactory keys.KeyPairFactory
	parent     *x509.Certificate
	signer     crypto.PrivateKey
	logger     *zerolog.Logger
}

func NewLocalCertificateFactory(template *x509.Certificate, keyFactory keys.KeyPairFactory, parent *x509.Certificate, signer crypto.PrivateKey) certs.CertificateFactory {
	logger := logging.RootLogger().With().Str("Provider", ProviderName).Logger()
	return &LocalCertificateFactory{
		template:   template,
		keyFactory: keyFactory,
		parent:     parent,
		signer:     signer,
		logger:     &logger,
	}
}

func (factory *LocalCertificateFactory) Name() string {
	return ProviderName
}

func (factory *LocalCertificateFactory) New() (crypto.PrivateKey, *x509.Certificate, error) {
	keyPair, err := factory.keyFactory.New()
	if err != nil {
		return nil, nil, err
	}
	var certificateBytes []byte
	if factory.parent != nil {
		// parent signed
		certificateBytes, err = x509.CreateCertificate(rand.Reader, factory.template, factory.parent, keyPair.Public(), factory.signer)
	} else {
		// self-signed
		certificateBytes, err = x509.CreateCertificate(rand.Reader, factory.template, factory.template, keyPair.Public(), keyPair.Private())
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate (cause: %w)", err)
	}
	certificate, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parse certificate bytes (cause: %w)", err)
	}
	return keyPair.Private(), certificate, nil
}
