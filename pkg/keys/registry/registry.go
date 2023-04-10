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

package registry

import (
	"github.com/hdecarne-github/certd/pkg/keys"
	"github.com/hdecarne-github/certd/pkg/keys/ecdsa"
	"github.com/hdecarne-github/certd/pkg/keys/ed25519"
	"github.com/hdecarne-github/certd/pkg/keys/rsa"
)

var providerNames = []string{}
var providerStandardKeys = make(map[string]func() []keys.KeyPairFactory, 0)
var standardKeys = make(map[string]keys.KeyPairFactory, 0)

func KeyProviders() []string {
	names := providerNames
	return names
}

func StandardKeys(name string) []keys.KeyPairFactory {
	return providerStandardKeys[name]()
}

func StandardKey(name string) keys.KeyPairFactory {
	return standardKeys[name]
}

func init() {
	providerNames = append(providerNames, ecdsa.ProviderName, ed25519.ProviderName, rsa.ProviderName)
	providerStandardKeys[ecdsa.ProviderName] = ecdsa.StandardKeys
	for _, key := range ecdsa.StandardKeys() {
		standardKeys[key.Name()] = key
	}
	providerStandardKeys[ed25519.ProviderName] = ed25519.StandardKeys
	for _, key := range ed25519.StandardKeys() {
		standardKeys[key.Name()] = key
	}
	providerStandardKeys[rsa.ProviderName] = rsa.StandardKeys
	for _, key := range rsa.StandardKeys() {
		standardKeys[key.Name()] = key
	}
}
