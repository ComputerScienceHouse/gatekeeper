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

package tasks

import (
	"errors"
	"fmt"
	"github.com/ComputerScienceHouse/gatekeeper/device"
	"github.com/ComputerScienceHouse/gatekeeper/keys"
	"github.com/ComputerScienceHouse/gatekeeper/sig"
	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"net/http"
)

const taskTypeVerify = "verify"

type taskVerify struct {
	ID      uuid.UUID     `json:"id"`
	Type    string        `json:"type"`
	Request *issueRequest `json:"-"`
	Output  chanWriter    `json:"-"`
	Logger  log.Logger    `json:"-"`
}

func (m *taskVerify) TaskType() string {
	return taskTypeVerify
}

func (m *taskVerify) GetOutput() chanWriter {
	return m.Output
}

func (m *taskVerify) LogError(err error) {
	m.Logger.Errorf("[ERROR] %s", err)
	m.Logger.Errorf("Aborting")
}

func (m *taskVerify) Run() {
	m.Logger.Info("Parsing verify request...")

	_, err := keys.Decode(m.Request.SystemSecret)
	if err != nil {
		m.LogError(err)
		return
	}

	var realms []device.Realm

	for _, realm := range m.Request.Realms {
		if realm.Slot < 0 || realm.Slot > 15 {
			m.LogError(errors.New("invalid slot number for realm, must be between 0-14"))
			return
		}

		slot := uint32(realm.Slot)

		associationId, err := uuid.Parse(realm.AssociationId)
		if err != nil {
			m.LogError(err)
			return
		}

		authKey, err := keys.Decode(realm.AuthKey)
		if err != nil {
			m.LogError(err)
			return
		}

		readKey, err := keys.Decode(realm.ReadKey)
		if err != nil {
			m.LogError(err)
			return
		}

		updateKey, err := keys.Decode(realm.UpdateKey)
		if err != nil {
			m.LogError(err)
			return
		}

		privateKey, publicKey, err := sig.Decode(realm.PrivateKey, realm.PublicKey)
		if err != nil {
			m.LogError(err)
			return
		}

		realms = append(realms, device.Realm{
			Name:          realm.Name,
			Slot:          slot,
			AssociationID: associationId,
			AuthKey:       authKey,
			ReadKey:       readKey,
			UpdateKey:     updateKey,
			PublicKey:     publicKey,
			PrivateKey:    privateKey,
		})
	}

	m.Logger.Info("Opening NFC device...")

	nfcDevice, err := device.OpenNFCDevice(m.Logger)
	if err != nil {
		m.LogError(err)
		return
	}

	target, err := nfcDevice.Connect(m.Logger)
	if err != nil {
		m.LogError(err)
		err = nfcDevice.Close(m.Logger)
		if err != nil {
			m.LogError(err)
		}
		return
	}

	for _, realm := range realms {
		m.Logger.Infof("Verifying tag for '%s' realm...", realm.Name)

		tagUUID, err := nfcDevice.Authenticate(*target, realm, m.Logger)
		if err != nil {
			m.LogError(errors.New("unable to authenticate tag"))
			err = nfcDevice.Close(m.Logger)
			if err != nil {
				m.LogError(err)
			}
			return
		}

		if tagUUID.String() != realm.AssociationID.String() {
			m.LogError(errors.New(fmt.Sprintf(
				"invalid UUID read from tag for realm '%s': expected '%s', got '%s'",
				realm.Name,
				realm.AssociationID.String(),
				tagUUID.String())))
			err = nfcDevice.Close(m.Logger)
			if err != nil {
				m.LogError(err)
			}
			return
		}
	}

	m.Logger.Info("Closing NFC device...")

	err = nfcDevice.Close(m.Logger)
	if err != nil {
		m.LogError(err)
		return
	}

	m.Logger.Info("Success")
}

func NewTaskVerify(request *issueRequest) (*taskVerify, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	output := newChanWriter()
	logger := log.New(fmt.Sprintf("verify_%s", id))
	logger.SetHeader("[${level}]")
	logger.SetOutput(output)

	return &taskVerify{
		ID:      id,
		Type:    taskTypeVerify,
		Request: request,
		Output:  *output,
		Logger:  *logger,
	}, nil
}

func CreateVerifyTask(c echo.Context) error {
	req := new(issueRequest)
	if err := c.Bind(req); err != nil {
		return err
	}

	task, err := NewTaskVerify(req)
	if err != nil {
		return err
	}

	taskStore[task.ID] = task
	c.Logger().Info(fmt.Sprintf("Created '%s' task: %s", task.Type, task.ID.String()))
	go task.Run()

	taskURL := c.Echo().URL(GetTask, task.ID.String())
	c.Response().Header().Set(echo.HeaderLocation, taskURL)
	return c.NoContent(http.StatusSeeOther)
}
