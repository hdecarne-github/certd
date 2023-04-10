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

package asn1

import (
	"bufio"
	_ "embed"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
)

//go:embed well-known-oids.txt
var wellKnownOIDS string
var wellKnownOIDSMap map[string]string = initWellKnownOIDSMap()

func initWellKnownOIDSMap() map[string]string {
	oidsMap := make(map[string]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(wellKnownOIDS))
	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.SplitN(line, ":", 2)
		if len(tokens) == 2 {
			oidsMap[strings.TrimSpace(tokens[0])] = fmt.Sprintf(" -- %s", strings.TrimSpace(tokens[1]))
		}
	}
	return oidsMap
}

func DecodeASN1(out io.Writer, data []byte) error {
	return decodeASN1(out, data, "")
}

func decodeASN1(out io.Writer, data []byte, indent string) error {
	var decoded asn1.RawValue
	rest, err := asn1.Unmarshal(data, &decoded)
	for {
		if err != nil {
			fmt.Fprintf(out, "Decode failure: %s", err.Error())
			return err
		}
		if decoded.IsCompound || (decoded.Tag == asn1.TagOctetString && len(decoded.Bytes) > 1 && decoded.Bytes[0] == 0x30) {
			fmt.Fprintf(out, "%s%s ::= {\n", indent, tagName(decoded.Tag))
			err = decodeASN1(out, decoded.Bytes, nestedIndent(indent))
			fmt.Fprintf(out, "%s}\n", indent)
		} else if decoded.Tag == asn1.TagBitString && len(decoded.Bytes) > 2 && decoded.Bytes[0] == 0x00 && decoded.Bytes[1] == 0x30 {
			fmt.Fprintf(out, "%s%s ::= {\n", indent, tagName(decoded.Tag))
			err = decodeASN1(out, decoded.Bytes[1:], nestedIndent(indent))
			fmt.Fprintf(out, "%s}\n", indent)
		} else {
			err = decodeValue(out, &decoded, indent)
		}
		if err != nil {
			continue
		}
		if len(rest) == 0 {
			break
		}
		rest, err = asn1.Unmarshal(rest, &decoded)
	}
	return nil
}

func decodeValue(out io.Writer, value *asn1.RawValue, indent string) error {
	return tagDecodeFunc(value.Tag)(out, value, indent)
}

func decodeBooleanValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var booleanValue bool
	_, err := asn1.Unmarshal(value.FullBytes, &booleanValue)
	if err != nil {
		return err
	}
	var booleanString string
	if booleanValue {
		booleanString = "TRUE"
	} else {
		booleanString = "FALSE"
	}
	fmt.Fprintf(out, "%s%s ::= %s\n", indent, tagName(value.Tag), booleanString)
	return nil
}

func decodeIntegerValue(out io.Writer, value *asn1.RawValue, indent string) error {
	if len(value.Bytes) > 8 {
		return decodeRawValue(out, value, indent)
	}
	var integerValue *big.Int
	_, err := asn1.Unmarshal(value.FullBytes, &integerValue)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s%s ::= %s\n", indent, tagName(value.Tag), integerValue.String())
	return nil
}

func decodeBitStringValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var bitStringValue asn1.BitString
	_, err := asn1.Unmarshal(value.FullBytes, &bitStringValue)
	if err != nil {
		return err
	}
	preamble0 := fmt.Sprintf("%s%s ::= ", indent, tagName(value.Tag))
	decodeBytes(out, bitStringValue.Bytes, indent, preamble0)
	return nil
}

func decodeOctetStringValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var octetStringValue []byte
	_, err := asn1.Unmarshal(value.FullBytes, &octetStringValue)
	if err != nil {
		return err
	}
	preamble0 := fmt.Sprintf("%s%s ::= ", indent, tagName(value.Tag))
	decodeBytes(out, octetStringValue, indent, preamble0)
	return nil
}

func decodeOIDValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var oidValue asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(value.FullBytes, &oidValue)
	if err != nil {
		return err
	}
	oidString := oidValue.String()
	oidName := wellKnownOIDSMap[oidString]
	fmt.Fprintf(out, "%s%s ::= %s%s\n", indent, tagName(value.Tag), oidString, oidName)
	return nil
}

func decodeStringValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var stringValue string
	_, err := asn1.Unmarshal(value.FullBytes, &stringValue)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s%s ::= \"%s\"\n", indent, tagName(value.Tag), stringValue)
	return nil
}

func decodeTimeValue(out io.Writer, value *asn1.RawValue, indent string) error {
	var utcTimeValue time.Time
	_, err := asn1.Unmarshal(value.FullBytes, &utcTimeValue)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%s%s ::= %s\n", indent, tagName(value.Tag), utcTimeValue)
	return nil
}

func decodeRawValue(out io.Writer, value *asn1.RawValue, indent string) error {
	preamble0 := fmt.Sprintf("%s%s ::= ", indent, tagName(value.Tag))
	decodeBytes(out, value.Bytes, indent, preamble0)
	return nil
}

func decodeBytes(out io.Writer, bytes []byte, indent string, preamble0 string) {
	preamble1 := continuationIndent(indent) + strings.Repeat(" ", len(preamble0)-len(indent))
	bytesLen := len(bytes)
	for bytesStart := 0; bytesStart < bytesLen; bytesStart += 16 {
		if bytesStart == 0 {
			fmt.Fprint(out, preamble0)
		} else {
			fmt.Fprint(out, preamble1)
		}
		nextBytesStart := bytesStart + 16
		if nextBytesStart < bytesLen {
			fmt.Fprintf(out, "%x\n", bytes[bytesStart:nextBytesStart])
		} else {
			fmt.Fprintf(out, "%x\n", bytes[bytesStart:])
		}
	}
}

var tagNames = map[int]string{
	asn1.TagBoolean:         "BOOLEAN",
	asn1.TagInteger:         "INTEGER",
	asn1.TagBitString:       "BIT STRING",
	asn1.TagOctetString:     "OCTET STRING",
	asn1.TagNull:            "NULL",
	asn1.TagOID:             "OID",
	asn1.TagEnum:            "ENUMERATED",
	asn1.TagUTF8String:      "UTF8String",
	asn1.TagSequence:        "SEQUENCE",
	asn1.TagSet:             "SET",
	asn1.TagNumericString:   "NumericString",
	asn1.TagPrintableString: "PrintableString",
	asn1.TagT61String:       "T61String",
	asn1.TagIA5String:       "IA5String",
	asn1.TagUTCTime:         "UTCTime",
	asn1.TagGeneralizedTime: "GeneralizedTime",
	asn1.TagGeneralString:   "GeneralString",
	asn1.TagBMPString:       "BMPString",
}

func tagName(tag int) string {
	name := tagNames[tag]
	if name == "" {
		name = "Tag(" + strconv.Itoa(tag) + ")"
	}
	return name
}

type decodeValueFunc func(io.Writer, *asn1.RawValue, string) error

var tagDecodeFuncs = map[int]decodeValueFunc{
	asn1.TagBoolean:         decodeBooleanValue,
	asn1.TagInteger:         decodeIntegerValue,
	asn1.TagBitString:       decodeBitStringValue,
	asn1.TagOctetString:     decodeOctetStringValue,
	asn1.TagNull:            decodeRawValue,
	asn1.TagOID:             decodeOIDValue,
	asn1.TagEnum:            decodeRawValue,
	asn1.TagUTF8String:      decodeStringValue,
	asn1.TagSequence:        decodeRawValue,
	asn1.TagSet:             decodeRawValue,
	asn1.TagNumericString:   decodeStringValue,
	asn1.TagPrintableString: decodeStringValue,
	asn1.TagT61String:       decodeRawValue,
	asn1.TagIA5String:       decodeStringValue,
	asn1.TagUTCTime:         decodeTimeValue,
	asn1.TagGeneralizedTime: decodeTimeValue,
	asn1.TagGeneralString:   decodeRawValue,
	asn1.TagBMPString:       decodeRawValue,
}

func tagDecodeFunc(tag int) decodeValueFunc {
	decodeFunc := tagDecodeFuncs[tag]
	if decodeFunc == nil {
		decodeFunc = decodeRawValue
	}
	return decodeFunc
}

func nestedIndent(indent string) string {
	return "  " + indent
}

func continuationIndent(indent string) string {
	return indent
}
