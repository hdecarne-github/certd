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

package certs

import (
	"crypto"
	"crypto/x509"
)

type Store interface {
	Name() string
	Entries() StoreEntries
}

type StoreEntry interface {
	Name() string
	Store() Store
	PrivateKey() (crypto.PrivateKey, error)
	Certificate() (*x509.Certificate, error)
}

type StoreEntries interface {
	Reset()
	Next() StoreEntry
}
