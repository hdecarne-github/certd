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

package remote

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

const ProviderName = "Remote"

type LocalCertificateRequestFactory struct {
	template   *x509.CertificateRequest
	keyFactory keys.KeyPairFactory
	logger     *zerolog.Logger
}

func NewLocalCertificateRequestFactory(template *x509.CertificateRequest, keyFactory keys.KeyPairFactory) certs.CertificateRequestFactory {
	logger := logging.RootLogger().With().Str("Provider", ProviderName).Logger()
	return &LocalCertificateRequestFactory{
		template:   template,
		keyFactory: keyFactory,
		logger:     &logger,
	}
}

func (factory *LocalCertificateRequestFactory) Name() string {
	return ProviderName
}

func (factory *LocalCertificateRequestFactory) New() (crypto.PrivateKey, *x509.CertificateRequest, error) {
	keyPair, err := factory.keyFactory.New()
	if err != nil {
		return nil, nil, err
	}
	certificateRequestBytes, err := x509.CreateCertificateRequest(rand.Reader, factory.template, keyPair.Private())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request (cause: %w)", err)
	}
	certificateRequest, err := x509.ParseCertificateRequest(certificateRequestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed parse certificate request bytes (cause: %w)", err)
	}
	return keyPair.Private(), certificateRequest, nil
}
