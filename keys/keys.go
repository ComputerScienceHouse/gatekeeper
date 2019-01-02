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

package keys

import (
	"crypto/rand"
	"github.com/fuzxxl/freefare/0.3/freefare"
)

func GenDESFireKey(key []byte) *freefare.DESFireKey {
	var keyArr [16]byte
	copy(keyArr[:], key[:])
	return freefare.NewDESFireAESKey(keyArr, 0)
}

func GenRandomDESFireKey() (*freefare.DESFireKey, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return GenDESFireKey(key), nil
}
