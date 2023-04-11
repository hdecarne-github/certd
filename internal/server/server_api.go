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

package server

import (
	"crypto/x509"
	"time"
)

// <- /api/about
type AboutResponse struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

// <- /api/store/entries
type StoreEntriesResponse struct {
	Entries []StoreEntryResponse `json:"entries"`
}

type StoreEntryResponse struct {
	Name      string    `json:"name"`
	DN        string    `json:"dn"`
	Key       bool      `json:"key"`
	CRT       bool      `json:"crt"`
	CSR       bool      `json:"csr"`
	CRL       bool      `json:"crl"`
	CA        bool      `json:"ca"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

// <- /api/store/entry/detail/:name
type StoreEntryDetailsResponse struct {
	StoreEntryResponse
	CRTDetails StoreEntryCRTDetailsResponse `json:"crt_details"`
}

type StoreEntryCRTDetailsResponse struct {
	Version    int         `json:"version"`
	Serial     string      `json:"serial"`
	KeyType    string      `json:"key_type"`
	Issuer     string      `json:"issuer"`
	SigAlg     string      `json:"sig_alg"`
	Extensions [][2]string `json:"extensions"`
}

// <- /api/store/cas
type StoreCAsResponse struct {
	CAs []StoreCAResponse `json:"cas"`
}

type StoreCAResponse struct {
	Name string `json:"name"`
}

// <- /api/store/local/issuers
type StoreLocalIssuersResponse struct {
	Issuers []StoreLocalIssuerResponse `json:"issuers"`
}

type StoreLocalIssuerResponse struct {
	Name string `json:"name"`
}

// <- /api/store/local/generate
type StoreGenerateLocalRequest struct {
	StoreGenerateRequest
	DN              string                       `json:"dn"`
	KeyType         string                       `json:"key_type"`
	Issuer          string                       `json:"issuer"`
	ValidFrom       time.Time                    `json:"valid_from"`
	ValidTo         time.Time                    `json:"valid_to"`
	KeyUsage        KeyUsageExtensionSpec        `json:"key_usage"`
	ExtKeyUsage     ExtKeyUsageExtensionSpec     `json:"ext_key_usage"`
	BasicConstraint BasicConstraintExtensionSpec `json:"basic_constraint"`
}

type StoreGenerateRequest struct {
	Name string `json:"name"`
	CA   string `json:"ca"`
}

type ExtensionSpec struct {
	Enabled bool `json:"enabled"`
}

type KeyUsageExtensionSpec struct {
	ExtensionSpec
	DigitalSignature  bool `json:"digital_signature"`
	ContentCommitment bool `json:"content_commitment"`
	KeyEncipherment   bool `json:"key_encipherment"`
	DataEncipherment  bool `json:"data_Encipherment"`
	KeyAgreement      bool `json:"key_agreement"`
	CertSign          bool `json:"cert_sign"`
	CRLSign           bool `json:"crl_sign"`
	EncipherOnly      bool `json:"encipher_only"`
	DecipherOnly      bool `json:"decipher_only"`
}

func (spec *KeyUsageExtensionSpec) toKeyUsage() x509.KeyUsage {
	keyUsage := x509.KeyUsage(0)
	if !spec.Enabled {
		return keyUsage
	}
	if spec.DigitalSignature {
		keyUsage |= x509.KeyUsageDigitalSignature
	}
	if spec.ContentCommitment {
		keyUsage |= x509.KeyUsageContentCommitment
	}
	if spec.KeyEncipherment {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}
	if spec.DataEncipherment {
		keyUsage |= x509.KeyUsageDataEncipherment
	}
	if spec.KeyAgreement {
		keyUsage |= x509.KeyUsageKeyAgreement
	}
	if spec.CertSign {
		keyUsage |= x509.KeyUsageCertSign
	}
	if spec.CRLSign {
		keyUsage |= x509.KeyUsageCRLSign
	}
	if spec.EncipherOnly {
		keyUsage |= x509.KeyUsageEncipherOnly
	}
	if spec.DecipherOnly {
		keyUsage |= x509.KeyUsageDecipherOnly
	}
	return keyUsage
}

type ExtKeyUsageExtensionSpec struct {
	ExtensionSpec
	Any                            bool `json:"any"`
	ServerAuth                     bool `json:"server_auth"`
	ClientAuth                     bool `json:"client_auth"`
	CodeSigning                    bool `json:"code_signing"`
	EmailProtection                bool `json:"email_protection"`
	IPSECEndSystem                 bool `json:"ipsec_end_system"`
	IPSECTunnel                    bool `json:"ipsec_tunnel"`
	IPSECUser                      bool `json:"ipsec_user"`
	TimeStamping                   bool `json:"time_stamping"`
	OCSPSigning                    bool `json:"ocsp_signing"`
	MicrosoftServerGatedCrypto     bool `json:"microsoft_server_gated_crypto"`
	NetscapeServerGatedCrypto      bool `json:"netscape_server_gated_crypto"`
	MicrosoftCommercialCodeSigning bool `json:"microsoft_commercial_code_signing"`
	MicrosoftKernelCodeSigning     bool `json:"microsoft_kernel_code_signing"`
}

func (spec *ExtKeyUsageExtensionSpec) toExtKeyUsage() []x509.ExtKeyUsage {
	if !spec.Enabled {
		return nil
	}
	extKeyUsage := make([]x509.ExtKeyUsage, 0)
	if spec.Any {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageAny)
	}
	if spec.ServerAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if spec.ClientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}
	if spec.CodeSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageCodeSigning)
	}
	if spec.EmailProtection {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageEmailProtection)
	}
	if spec.IPSECEndSystem {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECEndSystem)
	}
	if spec.IPSECTunnel {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECTunnel)
	}
	if spec.IPSECUser {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageIPSECUser)
	}
	if spec.TimeStamping {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageTimeStamping)
	}
	if spec.OCSPSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageOCSPSigning)
	}
	if spec.MicrosoftServerGatedCrypto {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftServerGatedCrypto)
	}
	if spec.NetscapeServerGatedCrypto {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageNetscapeServerGatedCrypto)
	}
	if spec.MicrosoftCommercialCodeSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftCommercialCodeSigning)
	}
	if spec.MicrosoftKernelCodeSigning {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageMicrosoftKernelCodeSigning)
	}
	return extKeyUsage
}

type BasicConstraintExtensionSpec struct {
	ExtensionSpec
	CA      bool `json:"ca"`
	PathLen int  `json:"path_len"`
}

func (spec *BasicConstraintExtensionSpec) applyToCertificate(certificate *x509.Certificate) {
	if spec.Enabled {
		certificate.IsCA = spec.CA
		if spec.CA && spec.PathLen >= 0 {
			certificate.MaxPathLen = spec.PathLen
			certificate.MaxPathLenZero = true
		} else {
			certificate.MaxPathLen = -1
			certificate.MaxPathLenZero = false
		}
	}
	certificate.BasicConstraintsValid = spec.Enabled
}

// <- /api/store/remote/generate
type StoreGenerateRemoteRequest struct {
	StoreGenerateRequest
	DN      string `json:"dn"`
	KeyType string `json:"key_type"`
}

// <- /api/store/acme/generate
type StoreGenerateACMERequest struct {
	StoreGenerateRequest
	Domains []string `json:"domains"`
	KeyType string   `json:"key_type"`
}

// <- /api/*
type ServerErrorResponse struct {
	Message string `json:"message"`
}
