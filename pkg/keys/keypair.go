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

package keys

import (
	"crypto"
	"crypto/elliptic"
)

type KeyPair interface {
	Public() crypto.PublicKey
	Private() crypto.PrivateKey
}

type KeyType int

const (
	Any     KeyType = 0
	RSA     KeyType = 1
	ECDSA   KeyType = 2
	ED25519 KeyType = 3
)

func (thisType KeyType) Is(keyType KeyType) bool {
	return thisType == Any || keyType == Any || thisType == keyType
}

type KeyPairFactory interface {
	Name() string
	New() (KeyPair, error)
}

func KeyPairFactories(keyType KeyType) []KeyPairFactory {
	factories := make([]KeyPairFactory, 0)
	if keyType.Is(RSA) {
		factories = append(factories, rsa2048KeyPairFactory, rsa3072KeyPairFactory, rsa4096KeyPairFactory)
	}
	if keyType.Is(ECDSA) {
		factories = append(factories, ecdsaP224KeyPairFactory, ecdsaP256KeyPairFactory, ecdsaP384KeyPairFactory, ecdsaP521KeyPairFactory)
	}
	if keyType.Is(ED25519) {
		factories = append(factories, ed25519KeyPairFactory)
	}
	return factories
}

type keyPairFactory struct {
	name string
	new  func() (KeyPair, error)
}

func (factory *keyPairFactory) Name() string {
	return factory.name
}

func (factory *keyPairFactory) New() (KeyPair, error) {
	return factory.new()
}

var rsa2048KeyPairFactory = &keyPairFactory{
	name: "RSA 2048",
	new:  func() (KeyPair, error) { return NewRSAKeyPair(2048) },
}

var rsa3072KeyPairFactory = &keyPairFactory{
	name: "RSA 3072",
	new:  func() (KeyPair, error) { return NewRSAKeyPair(3072) },
}

var rsa4096KeyPairFactory = &keyPairFactory{
	name: "RSA 4096",
	new:  func() (KeyPair, error) { return NewRSAKeyPair(4096) },
}

var ecdsaP224KeyPairFactory = &keyPairFactory{
	name: "ECDSA P224",
	new:  func() (KeyPair, error) { return NewECDSAKeyPair(elliptic.P224()) },
}

var ecdsaP256KeyPairFactory = &keyPairFactory{
	name: "ECDSA P256",
	new:  func() (KeyPair, error) { return NewECDSAKeyPair(elliptic.P256()) },
}

var ecdsaP384KeyPairFactory = &keyPairFactory{
	name: "ECDSA P384",
	new:  func() (KeyPair, error) { return NewECDSAKeyPair(elliptic.P384()) },
}

var ecdsaP521KeyPairFactory = &keyPairFactory{
	name: "ECDSA P521",
	new:  func() (KeyPair, error) { return NewECDSAKeyPair(elliptic.P521()) },
}

var ed25519KeyPairFactory = &keyPairFactory{
	name: "ED25519",
	new:  func() (KeyPair, error) { return NewED25519KeyPair() },
}
