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
	"crypto"
	"crypto/hmac"
	"github.com/fuzxxl/freefare/0.3/freefare"
)

const kdfHMACAlgorithm = crypto.SHA512

func DeriveDESFireKey(secret []byte, appId freefare.DESFireAid, keyNum uint8, data []byte) (*freefare.DESFireKey, error) {
	mac := hmac.New(kdfHMACAlgorithm.New, secret)

	if _, err := mac.Write([]byte{appId[0], appId[1], appId[2]}); err != nil {
		return nil, err
	}

	if _, err := mac.Write([]byte{keyNum}); err != nil {
		return nil, err
	}

	if _, err := mac.Write(data); err != nil {
		return nil, err
	}

	key := mac.Sum(nil)

	return GenDESFireKey(key), nil
}
