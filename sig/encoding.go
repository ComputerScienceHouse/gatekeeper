/*
	Copyright (C) 2019 Steven Mirabito (smirabito@csh.rit.edu)

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Lesser General Public License as published
	by the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Lesser General Public License for more details.

	You should have received a copy of the GNU Lesser General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package sig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func Encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (*string, *string, error) {
	encodedPrivateKey, err := EncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	encodedPublicKey, err := EncodePublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return encodedPrivateKey, encodedPublicKey, nil
}

func EncodePrivateKey(privateKey *ecdsa.PrivateKey) (*string, error) {
	x509Encoded, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemEncoded := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509Encoded,
	}))

	return &pemEncoded, nil
}

func EncodePublicKey(publicKey *ecdsa.PublicKey) (*string, error) {
	x509Encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pemEncoded := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509Encoded,
	}))

	return &pemEncoded, nil
}

func Decode(privateKey string, publicKey string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	decodedPrivateKey, err := DecodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	decodedPublicKey, err := DecodePublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	return decodedPrivateKey, decodedPublicKey, err
}

func DecodePrivateKey(pemEncoded string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func DecodePublicKey(pemEncoded string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPublicKey, ok := publicKey.(ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to parse PKIX block containing ECDSA public key")
	}

	return &ecdsaPublicKey, nil
}
