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
	"encoding/asn1"
	"sort"
	"strings"
)

const ExtKeyUsageExtensionName = "ExtKeyUsage"
const ExtKeyUsageExtensionOID = "2.5.29.37"

var extKeyUsageStrings = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "ServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
	x509.ExtKeyUsageEmailProtection:                "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
}

func ExtKeyUsageString(extKeyUsage []x509.ExtKeyUsage, unknownExtKeyUsage []asn1.ObjectIdentifier) string {
	if len(extKeyUsage) == 0 && len(unknownExtKeyUsage) == 0 {
		return "-"
	}
	usageStrings := make([]string, 0)
	for _, usage := range extKeyUsage {
		usageString := extKeyUsageStrings[usage]
		if usageString == "" {
			usageString = "?"
		}
		usageStrings = append(usageStrings, usageString)
	}
	for _, usage := range unknownExtKeyUsage {
		usageStrings = append(usageStrings, usage.String())
	}
	sort.Strings(usageStrings)
	var builder strings.Builder
	for _, usageString := range usageStrings {
		if builder.Len() > 0 {
			builder.WriteString(", ")
		}
		builder.WriteString(usageString)
	}
	return builder.String()
}
