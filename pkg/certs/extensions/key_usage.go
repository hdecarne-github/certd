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
	"crypto/x509"
	"sort"
	"strconv"
	"strings"
)

const KeyUsageExtensionName = "KeyUsage"
const KeyUsageExtensionOID = "2.5.29.15"

var keyUsageStrings = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "DigitalSignature",
	x509.KeyUsageContentCommitment: "ContentCommitment",
	x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
	x509.KeyUsageDataEncipherment:  "DataEncipherment",
	x509.KeyUsageKeyAgreement:      "KeyAgreement",
	x509.KeyUsageCertSign:          "CertSign",
	x509.KeyUsageCRLSign:           "CRLSign",
	x509.KeyUsageEncipherOnly:      "EncipherOnly",
	x509.KeyUsageDecipherOnly:      "DecipherOnly",
}

func KeyUsageString(keyUsage x509.KeyUsage) string {
	if keyUsage == 0 {
		return "-"
	}
	var keyUsageFlags x509.KeyUsage
	keyUsageFlagStrings := make([]string, 0)
	for keyUsageFlag, keyUsageFlagString := range keyUsageStrings {
		keyUsageFlags |= keyUsageFlag
		if (keyUsage & keyUsageFlag) == keyUsageFlag {
			keyUsageFlagStrings = append(keyUsageFlagStrings, keyUsageFlagString)
		}
	}
	unknownKeyUsage := keyUsage ^ keyUsageFlags
	if unknownKeyUsage != 0 {
		keyUsageFlagStrings = append(keyUsageFlagStrings, "0x"+strconv.FormatUint(uint64(unknownKeyUsage), 16))
	}
	sort.Strings(keyUsageFlagStrings)
	var builder strings.Builder
	for _, keyUsagekeyUsageFlagString := range keyUsageFlagStrings {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(keyUsagekeyUsageFlagString)
	}
	return builder.String()
}
