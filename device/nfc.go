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

package device

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ComputerScienceHouse/gatekeeper/keys"
	"github.com/ComputerScienceHouse/gatekeeper/sig"
	"github.com/fuzxxl/freefare/0.3/freefare"
	"github.com/fuzxxl/nfc/2.0/nfc"
	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"math/big"
	"strings"
	"time"
	"unsafe"
)

// The polling interval for reading a target
const targetLoopTimer = 50 * time.Millisecond

// baseAppId represents the first AID within a MiFare Classic mapped AID
// (0xF....?) in the middle (0x7F) of an unassigned function cluster (0xF7)
const baseAppId uint32 = 0xff77f0

// masterAppId represents the master AID, used for PICC master key derivation
const masterAppId uint32 = 0x0

// The default master/application key; for uninitialized cards and newly created applications, this is nil/all zeros
var (
	defaultKey        [16]byte
	defaultDESFireKey = freefare.NewDESFireAESKey(defaultKey, 0)
)

// MiFare application settings
const (
	initialApplicationSettings byte = 0x9
	finalApplicationSettings   byte = 0xE0
	initialPICCSettings        byte = 0x09
	finalPICCSettings          byte = 0x08
)

// MiFare file settings
const (
	initialUUIDFileSettings       uint16 = 0x0000
	finalUUIDFileSettings         uint16 = 0x1FFF
	finalAuthenticityFileSettings uint16 = 0x2F33
)

// UUID file parameters
const (
	mangledUUIDLength = 32
)

// Authenticity file parameters
const (
	authenticityRLength  = 32
	authenticitySLength  = 32
	authenticityFileSize = authenticityRLength + authenticitySLength
)

type nfcDevice struct {
	Device nfc.Device
}

type Realm struct {
	Name          string
	Slot          uint32
	AssociationID uuid.UUID
	AuthKey       []byte
	ReadKey       []byte
	UpdateKey     []byte
	PublicKey     *ecdsa.PublicKey
	PrivateKey    *ecdsa.PrivateKey
}

func OpenNFCDevice(log log.Logger) (*nfcDevice, error) {
	device, err := nfc.Open("")
	if err != nil {
		return nil, err
	}

	if err := device.InitiatorInit(); err != nil {
		return nil, err
	}

	log.Infof("NFC reader opened: %s", device.String())

	return &nfcDevice{
		Device: device,
	}, nil
}

func NFCHealthz() bool {
	nfcStatus := true

	nullLog := log.New("")
	nullLog.SetOutput(ioutil.Discard)

	nfcDevice, err := OpenNFCDevice(*nullLog)
	if err != nil || nfcDevice == nil {
		nfcStatus = false
	} else {
		_ = nfcDevice.Close(*nullLog)
	}

	return nfcStatus
}

func (d *nfcDevice) Close(log log.Logger) error {
	if err := d.Device.Close(); err != nil {
		return err
	}

	log.Infof("NFC device successfully closed")
	return nil
}

func (d *nfcDevice) Connect(log log.Logger) (*freefare.DESFireTag, error) {
	log.Infof("Waiting for card...")

	for {
		time.Sleep(targetLoopTimer)

		tags, err := freefare.GetTags(d.Device)
		if err != nil {
			log.Fatalf("Failed to get tags from device: %s", err)
			return nil, err
		}

		if len(tags) < 1 {
			// Keep polling until a tag is found
			continue
		}

		tag := tags[0]
		target, success := tag.(freefare.DESFireTag)
		if success != true {
			log.Warnf("Not a DESFire target, ignoring")
			continue
		}

		if err = target.Connect(); err != nil {
			// Can't connect to the tag
			log.Warnf("Unable to connect to target, ignoring: %s", err)
			continue
		}

		log.Infof("Connected to a %s target with UID %s", target.String(), target.UID())
		return &target, nil
	}
}

func (d *nfcDevice) Issue(target freefare.DESFireTag, systemSecret []byte, realms []Realm, log log.Logger) error {
	// Get the target's UID
	uid, err := target.CardUID()
	if err != nil {
		return nil
	}

	// Derive PICC master key
	mAppId := freefare.NewDESFireAid(masterAppId)
	piccMasterKey, err := keys.DeriveDESFireKey(systemSecret, mAppId, 0, []byte(uid))
	if err != nil {
		return nil
	}

	// Write each realm as an application
	for _, realm := range realms {
		appId := freefare.NewDESFireAid(baseAppId + realm.Slot)
		uuidArr := []byte(realm.AssociationID.String())
		mangledUUID := strings.Replace(realm.AssociationID.String(), "-", "", -1)

		if unsafe.Sizeof(mangledUUID) != mangledUUIDLength {
			return errors.New("unexpected size of mangled UUID")
		}

		// Derive app master key
		appMasterKey, err := keys.DeriveDESFireKey(systemSecret, appId, 0, []byte(uid))
		if err != nil {
			return nil
		}

		// Derive app transport keys
		appReadKey := keys.GenDESFireKey(realm.ReadKey)
		appAuthKey, err := keys.DeriveDESFireKey(systemSecret, appId, 2, uuidArr)
		if err != nil {
			return err
		}

		appUpdateKey, err := keys.DeriveDESFireKey(systemSecret, appId, 3, uuidArr)
		if err != nil {
			return err
		}

		// Sign the UUID and create the authenticity data
		rData, sData, err := sig.Sign(realm.PrivateKey, uuidArr)
		if err != nil {
			return err
		}

		rDataBytes := rData.Bytes()
		sDataBytes := sData.Bytes()

		if unsafe.Sizeof(rDataBytes) != authenticityRLength {
			return errors.New("unexpected size of authenticity data (R value)")
		}

		if unsafe.Sizeof(sDataBytes) != authenticitySLength {
			return errors.New("unexpected size of authenticity data (S value)")
		}

		// Ensure we're on the master application
		if err = target.SelectApplication(mAppId); err != nil {
			return nil
		}

		// Authenticate to the target
		if err = target.Authenticate(0, *defaultDESFireKey); err != nil {
			return nil
		}

		// Create the application
		if err = target.CreateApplication(appId, initialApplicationSettings, 4|freefare.CryptoAES); err != nil {
			return nil
		}

		// Select the newly created application
		if err = target.SelectApplication(appId); err != nil {
			return nil
		}

		// Authenticate to the application
		if err = target.Authenticate(0, *defaultDESFireKey); err != nil {
			return nil
		}

		// Change the application transport keys
		if err = target.ChangeKey(1, *appReadKey, *defaultDESFireKey); err != nil {
			return nil
		}

		if err = target.ChangeKey(2, *appAuthKey, *defaultDESFireKey); err != nil {
			return nil
		}

		if err = target.ChangeKey(3, *appUpdateKey, *defaultDESFireKey); err != nil {
			return nil
		}

		// Create the UUID data file
		if err = target.CreateDataFile(1, freefare.Plain, initialUUIDFileSettings, mangledUUIDLength, false); err != nil {
			return nil
		}

		dataLen, err := target.WriteData(1, 0, []byte(mangledUUID))
		if err != nil {
			return nil
		}

		if dataLen != mangledUUIDLength {
			return errors.New("failed to write UUID to target")
		}

		if err = target.ChangeFileSettings(1, freefare.Enciphered, finalUUIDFileSettings); err != nil {
			return nil
		}

		// Create the authenticity file
		if err = target.CreateDataFile(2, freefare.Enciphered, finalAuthenticityFileSettings, authenticityFileSize, false); err != nil {
			return nil
		}

		// Write the R value to the authenticity file
		dataLen, err = target.WriteData(2, 0, rDataBytes)
		if err != nil {
			return nil
		}

		if dataLen != authenticityRLength {
			return errors.New("failed to write authenticity file (R value) to target")
		}

		// Append the S value to the authenticity file
		dataLen, err = target.WriteData(2, authenticityRLength, sDataBytes)
		if err != nil {
			return nil
		}

		if dataLen != authenticitySLength {
			return errors.New("failed to write authenticity file (S value) to target")
		}

		// Change the application master key
		if err = target.ChangeKey(0, *appMasterKey, *defaultDESFireKey); err != nil {
			return nil
		}

		// Re-authenticate to the application
		if err = target.Authenticate(0, *appMasterKey); err != nil {
			return nil
		}

		// Change the application key settings
		if err = target.ChangeKeySettings(finalApplicationSettings); err != nil {
			return nil
		}
	}

	// Switch back to the master application
	if err = target.SelectApplication(mAppId); err != nil {
		return nil
	}

	// Authenticate to the target
	if err = target.Authenticate(0, *defaultDESFireKey); err != nil {
		return nil
	}

	// Change the key settings to allow us to change the PICC master key
	if err = target.ChangeKeySettings(initialPICCSettings); err != nil {
		return nil
	}

	// Change the PICC master key
	if err = target.ChangeKey(0, *piccMasterKey, *defaultDESFireKey); err != nil {
		return nil
	}

	// Re-authenticate to the target
	if err = target.Authenticate(0, *piccMasterKey); err != nil {
		return nil
	}

	// Set the final key settings
	if err = target.ChangeKeySettings(finalPICCSettings); err != nil {
		return nil
	}

	// Enable random UID
	if err = target.SetConfiguration(false, true); err != nil {
		return nil
	}

	// Successfully issued card
	return nil
}

func (d *nfcDevice) Authenticate(target freefare.DESFireTag, realm Realm, log log.Logger) (*uuid.UUID, error) {
	appId := freefare.NewDESFireAid(baseAppId + realm.Slot)
	appReadKey := keys.GenDESFireKey(realm.ReadKey)

	// Select the realm's application
	if err := target.SelectApplication(appId); err != nil {
		return nil, err
	}

	// Authenticate to the application
	if err := target.Authenticate(1, *appReadKey); err != nil {
		return nil, err
	}

	// Read the UUID from the application
	mangledUUID := make([]byte, mangledUUIDLength)
	dataLen, err := target.ReadData(1, 0, mangledUUID)
	if err != nil {
		return nil, err
	}

	if dataLen != mangledUUIDLength {
		return nil, errors.New("failed to read UUID from target")
	}

	// Parse the data read into a valid UUID
	targetUUID, err := uuid.ParseBytes(mangledUUID)
	if err != nil {
		return nil, err
	}

	// Derive the authentication key
	appAuthKey, err := keys.DeriveDESFireKey(realm.AuthKey, appId, 2, []byte(targetUUID.String()))
	if err != nil {
		return nil, err
	}

	// Authenticate with the derived key
	if err := target.Authenticate(2, *appAuthKey); err != nil {
		return nil, err
	}

	// Read the authenticity data (R value) from the target
	rDataBytes := make([]byte, authenticityRLength)
	dataLen, err = target.ReadData(2, 0, rDataBytes)
	if err != nil {
		return nil, err
	}

	if dataLen != authenticityRLength {
		return nil, errors.New("failed to read authenticity data (R value) from target")
	}

	// Read the authenticity data (S value) from the target
	sDataBytes := make([]byte, authenticitySLength)
	dataLen, err = target.ReadData(2, authenticityRLength, sDataBytes)
	if err != nil {
		return nil, err
	}

	if dataLen != authenticitySLength {
		return nil, errors.New("failed to read authenticity data (S value) from target")
	}

	// Verify UUID signature
	targetUUIDBytes := []byte(targetUUID.String())
	rData, sData := new(big.Int), new(big.Int)
	rData.SetBytes(rDataBytes)
	sData.SetBytes(sDataBytes)

	if !sig.Verify(realm.PublicKey, targetUUIDBytes, rData, sData) {
		return nil, errors.New("target UUID failed signature verification")
	}

	// Authenticated, return the UUID
	return &targetUUID, nil
}

func (d *nfcDevice) Disconnect(target freefare.DESFireTag, log log.Logger) error {
	if err := target.Disconnect(); err != nil {
		log.Warnf("Unable to disconnect from target (already disconnected?): %s", err)
		return err
	}

	log.Infof("Disconnected from target %s", target.UID())
	return nil
}
