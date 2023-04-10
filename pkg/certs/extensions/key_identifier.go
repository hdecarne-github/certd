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
package extensions

import (
	"encoding/hex"
	"strings"
)

const SubjectKeyIdentifierExtensionName = "SubjectKeyIdentifier"
const SubjectKeyIdentifierExtensionOID = "2.5.29.14"

const AuthorityKeyIdentifierExtensionName = "AuthorityKeyIdentifier"
const AuthorityKeyIdentifierExtensionOID = "2.5.29.35"

const stringLimit = 32

func KeyIdentifierString(keyId []byte) string {
	if len(keyId) == 0 {
		return ""
	}
	var builder strings.Builder
	encoder := hex.NewEncoder(&builder)
	for i, _ := range keyId {
		if i >= stringLimit {
			builder.WriteString(":...")
			break
		}
		if builder.Len() > 0 {
			builder.WriteString(":")
		}
		encoder.Write(keyId[i : i+1])
	}
	return builder.String()
}
