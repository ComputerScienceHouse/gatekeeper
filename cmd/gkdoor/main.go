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
	"github.com/labstack/gommon/log"
)

func main() {
	logger := log.New("")
	logger.SetHeader("[${level}]")

	nfcDevice, err := device.OpenNFCDevice(*logger)
	if err != nil {
		logger.Fatalf("unable to connect to NFC device")
	}

	for {
		target, err := nfcDevice.Connect(*logger)
		if err != nil {
			logger.Fatalf("unable to connect to target")
		}


	}
}
