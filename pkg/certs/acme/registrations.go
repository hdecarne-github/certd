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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/hdecarne-github/certd/internal/state"
	"github.com/hdecarne-github/certd/pkg/keys"
)

const providerRegistrationsFile = "acme-registrations.json"

var providerRegistrationsFileMutex sync.RWMutex

type ProviderRegistration struct {
	Provider     string `json:"provider"`
	Email        string `json:"email"`
	Key          string `json:"key"`
	Registration *registration.Resource
}

func (providerRegistration *ProviderRegistration) GetEmail() string {
	return providerRegistration.Email
}

func (providerRegistration *ProviderRegistration) GetRegistration() *registration.Resource {
	return providerRegistration.Registration
}

func (providerRegistration *ProviderRegistration) GetPrivateKey() crypto.PrivateKey {
	if providerRegistration.Key == "" {
		return nil
	}
	keyBytes, err := base64.StdEncoding.DecodeString(providerRegistration.Key)
	if err != nil {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil
	}
	return key
}

func (providerRegistration *ProviderRegistration) isValid(client *lego.Client) bool {
	if providerRegistration.Registration == nil {
		return false
	}
	_, err := client.Registration.QueryRegistration()
	return err == nil
}

func (providerRegistration *ProviderRegistration) refresh(client *lego.Client, keyFactory keys.KeyPairFactory) error {
	options := registration.RegisterOptions{TermsOfServiceAgreed: true}
	registration, err := client.Registration.Register(options)
	if err != nil {
		return fmt.Errorf("failed to register at ACME provider '%s' (cause: %w)", providerRegistration.Provider, err)
	}
	providerRegistration.Registration = registration
	return updateProviderRegistrations(providerRegistration)
}

func getRegistration(provider *Provider, keyFactory keys.KeyPairFactory) (*ProviderRegistration, error) {
	providerRegistrationsFileMutex.RLock()
	defer providerRegistrationsFileMutex.RUnlock()
	providerRegistrations, err := loadProviderRegistrations()
	if err != nil {
		return nil, err
	}
	for _, providerRegistration := range providerRegistrations {
		if providerRegistration.Provider == provider.Name && providerRegistration.Email == provider.RegistrationEmail {
			return &providerRegistration, nil
		}
	}
	key, err := keyFactory.New()
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key.Private())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key (cause: %w)", err)
	}
	defaultProviderRegistration := &ProviderRegistration{
		Provider: provider.Name,
		Email:    provider.RegistrationEmail,
		Key:      base64.StdEncoding.EncodeToString(keyBytes),
	}
	return defaultProviderRegistration, nil
}

func updateProviderRegistrations(update *ProviderRegistration) error {
	providerRegistrationsFileMutex.Lock()
	defer providerRegistrationsFileMutex.Unlock()
	providerRegistrations, err := loadProviderRegistrations()
	if err != nil {
		return err
	}
	updateIndex := -1
	for i, providerRegistration := range providerRegistrations {
		if providerRegistration.Provider == update.Provider && providerRegistration.Email == update.Email {
			updateIndex = i
			break
		}
	}
	if updateIndex >= 0 {
		providerRegistrations[updateIndex] = *update
	} else {
		providerRegistrations = append(providerRegistrations, *update)
	}
	providerRegistrationBytes, err := json.MarshalIndent(providerRegistrations, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal registrations (cause: %w)", err)
	}
	return state.Write(providerRegistrationsFile, providerRegistrationBytes)
}

func loadProviderRegistrations() ([]ProviderRegistration, error) {
	providerRegistrationsBytes, err := state.Read(providerRegistrationsFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read registrations from '%s' (cause: %w)", providerRegistrationsFile, err)
	}
	providerRegistrations := make([]ProviderRegistration, 0)
	if err == nil {
		err = json.Unmarshal(providerRegistrationsBytes, &providerRegistrations)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal registrations file '%s' (cause: %w)", providerRegistrationsFile, err)
		}
	}
	return providerRegistrations, nil
}
