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

package ecdsa

import (
	"crypto"
	algorithm "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/hdecarne-github/certd/pkg/keys"
)

const ProviderName = "ECDSA"

type ECDSAKeyPair struct {
	key *algorithm.PrivateKey
}

func NewECDSAKeyPair(curve elliptic.Curve) (keys.KeyPair, error) {
	key, err := algorithm.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ECDSAKeyPair{key: key}, nil
}

func (keypair *ECDSAKeyPair) Public() crypto.PublicKey {
	return keypair.key.Public()
}

func (keypair *ECDSAKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}

type ECDSAKeyPairFactory struct {
	curve elliptic.Curve
}

func NewECDSAKeyPairFactory(curve elliptic.Curve) keys.KeyPairFactory {
	return &ECDSAKeyPairFactory{curve: curve}
}

func (factory *ECDSAKeyPairFactory) Name() string {
	return ProviderName + " " + factory.curve.Params().Name
}

func (factory *ECDSAKeyPairFactory) New() (keys.KeyPair, error) {
	return NewECDSAKeyPair(factory.curve)
}

func StandardKeys() []keys.KeyPairFactory {
	return []keys.KeyPairFactory{
		NewECDSAKeyPairFactory(elliptic.P224()),
		NewECDSAKeyPairFactory(elliptic.P256()),
		NewECDSAKeyPairFactory(elliptic.P384()),
		NewECDSAKeyPairFactory(elliptic.P521()),
	}
}
