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

package rsa

import (
	"crypto"
	"crypto/rand"
	algorithm "crypto/rsa"
	"strconv"

	"github.com/hdecarne-github/certd/pkg/keys"
)

const ProviderName = "RSA"

type RSAKeyPair struct {
	key *algorithm.PrivateKey
}

func NewRSAKeyPair(bits int) (keys.KeyPair, error) {
	key, err := algorithm.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &RSAKeyPair{key: key}, nil
}

func (keypair *RSAKeyPair) Public() crypto.PublicKey {
	return &keypair.key.PublicKey
}

func (keypair *RSAKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

type RSAKeyPairFactory struct {
	bits int
}

func NewRSAKeyPairFactory(bits int) keys.KeyPairFactory {
	return &RSAKeyPairFactory{bits: bits}
}

func (factory *RSAKeyPairFactory) Name() string {
	return ProviderName + " " + strconv.Itoa(factory.bits)
}

func (factory *RSAKeyPairFactory) New() (keys.KeyPair, error) {
	return NewRSAKeyPair(factory.bits)
}

func StandardKeys() []keys.KeyPairFactory {
	return []keys.KeyPairFactory{
		NewRSAKeyPairFactory(2048),
		NewRSAKeyPairFactory(3072),
		NewRSAKeyPairFactory(4096),
	}
}
