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

package security

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Simple obfuscator, just to not keep the secret in plain sight.
type Secret struct {
	key     []byte
	wrapped []byte
}

func Wrap(secret string) (*Secret, error) {
	unwrapped := []byte(secret)
	s := &Secret{
		key:     make([]byte, len(unwrapped)),
		wrapped: make([]byte, len(unwrapped)),
	}
	_, err := io.ReadFull(rand.Reader, s.key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key (cause: %w)", err)
	}
	for i, x := range s.key {
		s.wrapped[i] = unwrapped[i] ^ x
	}
	return s, nil
}

func (s *Secret) UnwrapBytes() []byte {
	unwrapped := make([]byte, len(s.wrapped))
	for i, x := range s.key {
		unwrapped[i] = s.wrapped[i] ^ x
	}
	return unwrapped
}

func (s *Secret) Unwrap() string {
	return string(s.UnwrapBytes())
}
