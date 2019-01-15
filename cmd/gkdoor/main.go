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

package main

import (
	"github.com/ComputerScienceHouse/gatekeeper/device"
	"github.com/fuzxxl/freefare/0.3/freefare"
	"github.com/labstack/gommon/log"
)

// baseAppId represents the first AID within a MiFare Classic mapped AID
// (0xF....?) in the middle (0x7F) of an unassigned function cluster (0xF7)
const baseAppId uint32 = 0xff77f0

// The default master/application key; for uninitialized cards and newly created applications, this is all zeros
var (
	defaultDESKey        = [8]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	defaultDESFireDESKey = freefare.NewDESFireDESKey(defaultDESKey)
)

func main() {
	logger := log.New("")
	logger.SetHeader("[${level}]")

	nfcDevice, err := device.OpenNFCDevice(*logger)
	if err != nil {
		logger.Fatalf("unable to connect to NFC device")
	}

	target, err := nfcDevice.Connect(*logger)
	if err != nil {
		logger.Fatalf("unable to connect to target")
	}

	// Authenticate to the target
	logger.Infof("Authenticating to tag...")
	if err = target.Authenticate(0, *defaultDESFireDESKey); err != nil {
		logger.Fatalf("unable to authenticate to target")
	}

	// Format tag
	logger.Infof("Formatting tag...")
	if err = target.FormatPICC(); err != nil {
		logger.Fatalf("unable to format tag")
	}

	logger.Infof("Success")
}
