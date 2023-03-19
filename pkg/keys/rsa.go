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
	"crypto/rand"
	"crypto/rsa"
)

func NewRSAKeyPair(bits int) (KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{key: key}, nil
}

type rsaKeyPair struct {
	key *rsa.PrivateKey
}

func (keypair *rsaKeyPair) Public() crypto.PublicKey {
	return &keypair.key.PublicKey
}

func (keypair *rsaKeyPair) Private() crypto.PrivateKey {
	return keypair.key
}
