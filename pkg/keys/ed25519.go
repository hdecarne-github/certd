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
	"crypto/ed25519"
	"crypto/rand"
)

func NewED25519KeyPair() (KeyPair, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ed25519KeyPair{public: public, private: private}, nil
}

type ed25519KeyPair struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (keypair *ed25519KeyPair) Public() crypto.PublicKey {
	return keypair.public
}

func (keypair *ed25519KeyPair) Private() crypto.PrivateKey {
	return keypair.private
}
