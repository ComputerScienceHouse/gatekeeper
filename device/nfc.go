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
	"github.com/fuzxxl/freefare/0.3/freefare"
	"github.com/fuzxxl/nfc/2.0/nfc"
	"github.com/google/uuid"
	"github.com/labstack/gommon/log"
	"io/ioutil"
	"time"
)

// The polling interval for reading a target
const targetLoopTimer = 50 * time.Millisecond

// baseAppId represents the first AID within a MiFare Classic mapped AID
// (0xF....?) in the middle (0x7F) of an unassigned function cluster (0xF7)
const baseAppId uint32 = 0xff77f0

// masterAppId represents the master AID, used for PICC master key derivation
const masterAppId uint32 = 0

// The default master/application keys; for uninitialized cards and newly created applications, this is all zeros
var (
	defaultDESKey        = [8]byte{0x0}
	defaultAESKey        = [16]byte{0x0}
	defaultDESFireDESKey = freefare.NewDESFireDESKey(defaultDESKey)
	defaultDESFireAESKey = freefare.NewDESFireAESKey(defaultAESKey, 0)
)

// MiFare application settings
const (
	initialApplicationSettings byte = 0x9
	finalApplicationSettings   byte = 0xE0
	initialPICCSettings        byte = 0x09
	finalPICCSettings          byte = 0x08
)

// File ACLs
var (
	// Read: Key 0, Write: Key 0, Read & Write: Key 0, Change Access Rights: Key 0
	initialFileSettings = freefare.MakeDESFireAccessRights(0x0, 0x0, 0x0, 0x0)

	// Read: Key 1, Write: Never, Read & Write: Never, Change Access Rights: Never
	finalUUIDFileSettings = freefare.MakeDESFireAccessRights(0x1, 0xF, 0xF, 0xF)

	// Read: Key 2, Write: Never, Read & Write: Never, Change Access Rights: Key 3
	finalAuthenticityFileSettings = freefare.MakeDESFireAccessRights(0x2, 0xF, 0x3, 0x3)
)

// UUID file parameters
const (
	mangledUUIDLength = 32
)

// Authenticity file parameters
const (
	authenticityRLength  = 48
	authenticitySLength  = 48
	authenticityFileSize = authenticityRLength + authenticitySLength
)

type nfcDevice struct {
	device nfc.Device
}

type nfcTag struct {
	Target freefare.DESFireTag
	UID    []byte
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
		device: device,
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
	if err := d.device.Close(); err != nil {
		return err
	}

	log.Infof("NFC device successfully closed")
	return nil
}

func (d *nfcDevice) Connect(log log.Logger) (*nfcTag, error) {
	log.Infof("Waiting for card...")

	for {
		time.Sleep(targetLoopTimer)

		tags, err := freefare.GetTags(d.device)
		if err != nil {
			log.Errorf("Failed to get tags from device: %s", err)
			return nil, err
		}

		if len(tags) < 1 {
			// Keep polling until a tag is found
			continue
		}

		tag := tags[0]
		target, success := tag.(freefare.DESFireTag)
		if success != true {
			log.Warnf("tag not supported, must be DESFire EV1 or later")
			continue
		}

		if err = target.Connect(); err != nil {
			// Can't connect to the tag
			log.Warnf("Unable to connect to target, ignoring: %s", err)
			continue
		}

		// Set the communication modes
		target.WriteSettings = freefare.Enciphered
		target.ReadSettings = freefare.Enciphered

		// Retrieve tag version info
		version, err := target.Version()
		if err != nil {
			log.Warnf("failed to retrieve tag version info, please try again")
			continue
		}

		// Ensure target is at least a DESFire EV1 tag
		if version.Software.VersionMajor < 1 {
			return nil, errors.New("tag not supported, must be DESFire EV1 or later")
		}

		log.Infof("Connected to a %s target with UID %s", target.String(), target.UID())
		return &nfcTag{
			Target: target,
			UID:    version.UID[:],
		}, nil
	}
}

func (d *nfcDevice) Disconnect(target freefare.DESFireTag, log log.Logger) error {
	if err := target.Disconnect(); err != nil {
		log.Warnf("Unable to disconnect from target (already disconnected?): %s", err)
		return err
	}

	log.Infof("Disconnected from target %s", target.UID())
	return nil
}

func (t *nfcTag) Issue(systemSecret []byte, realms []Realm, log log.Logger) error {
	// Derive PICC master key
	log.Infof("Deriving PICC master key...")
	mAppId := freefare.NewDESFireAid(masterAppId)
	_, err := keys.DeriveDESFireKey(systemSecret, mAppId, 0, t.UID)
	if err != nil {
		return errors.New("failed to derive PICC master key")
	}

	// FIXME: Writing data to the card doesn't work in this implementation
	// Write each realm as an application
	//for _, realm := range realms {
	//	appId := freefare.NewDESFireAid(baseAppId + realm.Slot)
	//	uuidArr := []byte(realm.AssociationID.String())
	//	mangledUUID := strings.Replace(realm.AssociationID.String(), "-", "", -1)
	//
	//	if len(mangledUUID) != mangledUUIDLength {
	//		return errors.New("unexpected size of mangled UUID")
	//	}
	//
	//	log.Infof("Deriving application keys for '%s' realm...", realm.Name)
	//
	//	// Derive app master key
	//	appMasterKey, err := keys.DeriveDESFireKey(systemSecret, appId, 0, []byte(uid))
	//	if err != nil {
	//		return errors.New(fmt.Sprintf("failed to derive app master key for '%s' realm", realm.Name))
	//	}
	//
	//	// Derive app transport keys
	//	appReadKey := keys.GenDESFireKey(realm.ReadKey)
	//	appAuthKey, err := keys.DeriveDESFireKey(systemSecret, appId, 2, uuidArr)
	//	if err != nil {
	//		return err
	//	}
	//
	//	appUpdateKey, err := keys.DeriveDESFireKey(systemSecret, appId, 3, uuidArr)
	//	if err != nil {
	//		return err
	//	}
	//
	//	log.Infof("Creating authenticity data...")
	//
	//	// Sign the UUID and create the authenticity data
	//	rData, sData, err := sig.Sign(realm.PrivateKey, uuidArr)
	//	if err != nil {
	//		return err
	//	}
	//
	//	rDataBytes := rData.Bytes()
	//	sDataBytes := sData.Bytes()
	//
	//	if len(rDataBytes) != authenticityRLength {
	//		return errors.New("unexpected size of authenticity data (R value)")
	//	}
	//
	//	if len(sDataBytes) != authenticitySLength {
	//		return errors.New("unexpected size of authenticity data (S value)")
	//	}
	//
	//	// Ensure we're on the master application
	//	log.Infof("Switching to the master application...")
	//	if err = target.SelectApplication(mAppId); err != nil {
	//		return err
	//	}
	//
	//	// Authenticate to the target
	//	log.Infof("Authenticating to tag...")
	//	if err = target.Authenticate(0, *defaultDESFireDESKey); err != nil {
	//		return err
	//	}
	//
	//	// Create the application
	//	log.Infof("Creating application in slot %d...", realm.Slot)
	//	if err = target.CreateApplication(appId, initialApplicationSettings, 4|freefare.CryptoAES); err != nil {
	//		return err
	//	}
	//
	//	// Select the newly created application
	//	log.Infof("Selecting application...")
	//	if err = target.SelectApplication(appId); err != nil {
	//		return err
	//	}
	//
	//	// Authenticate to the application
	//	log.Infof("Authenticating to application...")
	//	if err = target.Authenticate(0, *defaultDESFireAESKey); err != nil {
	//		return err
	//	}
	//
	//	// Change the application transport keys
	//	log.Infof("Changing application transport keys...")
	//	if err = target.ChangeKey(1, *appReadKey, *defaultDESFireAESKey); err != nil {
	//		return err
	//	}
	//
	//	if err = target.ChangeKey(2, *appAuthKey, *defaultDESFireAESKey); err != nil {
	//		return err
	//	}
	//
	//	if err = target.ChangeKey(3, *appUpdateKey, *defaultDESFireAESKey); err != nil {
	//		return err
	//	}
	//
	//	// Create the UUID data file
	//	log.Infof("Writing UUID data file...")
	//	if err = target.CreateDataFile(1, freefare.Plain, initialFileSettings, mangledUUIDLength, false); err != nil {
	//		return err
	//	}
	//
	//	target.ReadSettings = freefare.Plain
	//	target.WriteSettings = freefare.Plain
	//
	//	dataLen, err := target.WriteData(1, 0, []byte(mangledUUID))
	//	if err != nil {
	//		return err
	//	}
	//
	//	if dataLen != mangledUUIDLength {
	//		return errors.New("failed to write UUID to target")
	//	}
	//
	//	// Create the authenticity file
	//	log.Infof("Writing authenticity file...")
	//	if err = target.CreateDataFile(2, freefare.Enciphered, initialFileSettings, authenticityFileSize, false); err != nil {
	//		return err
	//	}
	//
	//	// Write the R value to the authenticity file
	//	dataLen, err = target.WriteData(2, 0, rDataBytes)
	//	if err != nil {
	//		return err
	//	}
	//
	//	if dataLen != authenticityRLength {
	//		return errors.New("failed to write authenticity file (R value) to target")
	//	}
	//
	//	// Append the S value to the authenticity file
	//	dataLen, err = target.WriteData(2, authenticityRLength, sDataBytes)
	//	if err != nil {
	//		return err
	//	}
	//
	//	if dataLen != authenticitySLength {
	//		return errors.New("failed to write authenticity file (S value) to target")
	//	}
	//
	//	log.Infof("Applying file ACLs...")
	//	if err = target.ChangeFileSettings(1, freefare.Enciphered, finalUUIDFileSettings); err != nil {
	//		return err
	//	}
	//
	//	if err = target.ChangeFileSettings(2, freefare.Enciphered, finalAuthenticityFileSettings); err != nil {
	//		return err
	//	}
	//
	//	// Change the application master key
	//	log.Infof("Changing application master key...")
	//	if err = target.ChangeKey(0, *appMasterKey, *defaultDESFireAESKey); err != nil {
	//		return err
	//	}
	//
	//	// Re-authenticate to the application
	//	if err = target.Authenticate(0, *appMasterKey); err != nil {
	//		return err
	//	}
	//
	//	// Change the application key settings
	//	log.Infof("Finalizing application settings...")
	//	if err = target.ChangeKeySettings(finalApplicationSettings); err != nil {
	//		return err
	//	}
	//}
	//
	//// Switch back to the master application
	//log.Infof("Switching to the master application...")
	//if err = target.SelectApplication(mAppId); err != nil {
	//	return err
	//}
	//
	//// Authenticate to the target
	//log.Infof("Authenticating to tag...")
	//if err = target.Authenticate(0, *defaultDESFireDESKey); err != nil {
	//	return err
	//}

	// TODO: Actually change the PICC master key

	// Change the key settings to allow us to change the PICC master key
	//if err = target.ChangeKeySettings(initialPICCSettings); err != nil {
	//	return err
	//}

	// Change the PICC master key
	//log.Infof("Changing PICC master key...")
	//if err = target.ChangeKey(0, *piccMasterKey, *defaultDESFireDESKey); err != nil {
	//	return err
	//}

	// Re-authenticate to the target
	//if err = target.Authenticate(0, *piccMasterKey); err != nil {
	//	return err
	//}

	// Set the final key settings
	//log.Infof("Finalizing PICC settings...")
	//if err = target.ChangeKeySettings(finalPICCSettings); err != nil {
	//	return err
	//}

	// Enable random UID
	//log.Infof("Enabling random PICC UID...")
	//if err = target.SetConfiguration(false, true); err != nil {
	//	return err
	//}

	// Successfully issued card
	return nil
}

func (d *nfcTag) Authenticate(realm Realm, log log.Logger) error {
	// FIXME: Verify realm data written to card; doesn't work due to problem with writing in Issue()
	//appId := freefare.NewDESFireAid(baseAppId + realm.Slot)
	//appReadKey := keys.GenDESFireKey(realm.ReadKey)
	//
	//// Select the realm's application
	//if err := target.SelectApplication(appId); err != nil {
	//	return errors.New("failed to select realm application")
	//}
	//
	//// Authenticate to the application
	//if err := target.Authenticate(1, *appReadKey); err != nil {
	//	return errors.New("failed to authenticate to realm application")
	//}
	//
	//// Read the UUID from the application
	//mangledUUID := make([]byte, mangledUUIDLength)
	//dataLen, err := target.ReadData(1, 0, mangledUUID)
	//if err != nil {
	//	return err
	//}
	//
	//if dataLen != mangledUUIDLength {
	//	return errors.New("failed to read UUID from target")
	//}
	//
	//// Parse the data read into a valid UUID
	//targetUUID, err := uuid.ParseBytes(mangledUUID)
	//if err != nil {
	//	return err
	//}
	//
	//// Derive the authentication key
	//appAuthKey, err := keys.DeriveDESFireKey(realm.AuthKey, appId, 2, []byte(targetUUID.String()))
	//if err != nil {
	//	return err
	//}
	//
	//// Authenticate with the derived key
	//if err := target.Authenticate(2, *appAuthKey); err != nil {
	//	return err
	//}
	//
	//// Read the authenticity data (R value) from the target
	//rDataBytes := make([]byte, authenticityRLength)
	//dataLen, err = target.ReadData(2, 0, rDataBytes)
	//if err != nil {
	//	return err
	//}
	//
	//if dataLen != authenticityRLength {
	//	return errors.New("failed to read authenticity data (R value) from target")
	//}
	//
	//// Read the authenticity data (S value) from the target
	//sDataBytes := make([]byte, authenticitySLength)
	//dataLen, err = target.ReadData(2, authenticityRLength, sDataBytes)
	//if err != nil {
	//	return err
	//}
	//
	//if dataLen < authenticitySLength {
	//	return errors.New("failed to read authenticity data (S value) from target")
	//}
	//
	//// Verify UUID signature
	//targetUUIDBytes := []byte(targetUUID.String())
	//rData, sData := new(big.Int), new(big.Int)
	//rData.SetBytes(rDataBytes)
	//sData.SetBytes(sDataBytes)
	//
	//if !sig.Verify(realm.PublicKey, targetUUIDBytes, rData, sData) {
	//	return errors.New("target UUID failed signature verification")
	//}

	// Successfully authenticated
	return nil
}
