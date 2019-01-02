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
	"crypto/rand"
	"crypto/sha512"
	"math/big"
)

var ecdsaHashFunction = sha512.Sum512

func Sign(privateKey *ecdsa.PrivateKey, data []byte) (r, s *big.Int, err error) {
	hash := ecdsaHashFunction(data)
	return ecdsa.Sign(rand.Reader, privateKey, hash[:])
}

func Verify(publicKey *ecdsa.PublicKey, data []byte, r, s *big.Int) bool {
	hash := ecdsaHashFunction(data)
	return ecdsa.Verify(publicKey, hash[:], r, s)
}
