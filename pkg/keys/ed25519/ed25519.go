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

package ed25519

import (
	"crypto"
	algorithm "crypto/ed25519"
	"crypto/rand"

	"github.com/hdecarne-github/certd/pkg/keys"
)

const ProviderName = "ED25519"

type ED25519KeyPair struct {
	public  algorithm.PublicKey
	private algorithm.PrivateKey
}

func NewED25519KeyPair() (keys.KeyPair, error) {
	public, private, err := algorithm.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ED25519KeyPair{public: public, private: private}, nil
}

func (keypair *ED25519KeyPair) Public() crypto.PublicKey {
	return keypair.public
}

func (keypair *ED25519KeyPair) Private() crypto.PrivateKey {
	return keypair.private
}

type ED25519KeyPairFactory struct{}

func NewED25519KeyPairFactory() keys.KeyPairFactory {
	return &ED25519KeyPairFactory{}
}

func (factory *ED25519KeyPairFactory) Name() string {
	return ProviderName
}

func (factory *ED25519KeyPairFactory) New() (keys.KeyPair, error) {
	return NewED25519KeyPair()
}

func StandardKeys() []keys.KeyPairFactory {
	return []keys.KeyPairFactory{
		NewED25519KeyPairFactory(),
	}
}
