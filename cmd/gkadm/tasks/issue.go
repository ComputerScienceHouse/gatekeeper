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

const taskTypeIssue = "issue"

type issueRequest struct {
	SystemSecret string              `json:"systemSecret"`
	Realms       []issueRequestRealm `json:"realms"`
}

type issueRequestRealm struct {
	Name          string `json:"name"`
	Slot          int    `json:"slot"`
	AssociationId string `json:"associationId"`
	AuthKey       string `json:"authKey"`
	ReadKey       string `json:"readKey"`
	UpdateKey     string `json:"updateKey"`
	PublicKey     string `json:"publicKey"`
	PrivateKey    string `json:"privateKey"`
}

type taskIssue struct {
	ID      uuid.UUID     `json:"id"`
	Type    string        `json:"type"`
	Request *issueRequest `json:"-"`
	Output  chanWriter    `json:"-"`
	Logger  log.Logger    `json:"-"`
}

func (m *taskIssue) TaskType() string {
	return taskTypeIssue
}

func (m *taskIssue) GetOutput() chanWriter {
	return m.Output
}

func (m *taskIssue) LogError(err error) {
	m.Logger.Fatalf("[ERROR] %s", err)
	m.Logger.Fatalf("Aborting")
}

func (m *taskIssue) Run() {
	m.Logger.Info("Parsing issue request...")

	systemSecret, err := keys.Decode(m.Request.SystemSecret)
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
		return
	}

	m.Logger.Info("Writing tag...")

	err = nfcDevice.Issue(*target, systemSecret, realms, m.Logger)
	if err != nil {
		m.LogError(err)
		return
	}

	m.Logger.Info("Success")
}

func NewTaskIssue(request *issueRequest) (*taskIssue, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	output := newChanWriter()
	logger := log.New("")
	logger.SetOutput(output)

	return &taskIssue{
		ID:      id,
		Type:    taskTypeIssue,
		Request: request,
		Output:  *output,
		Logger:  *log.New(""),
	}, nil
}

func CreateIssueTask(c echo.Context) error {
	req := new(issueRequest)
	if err := c.Bind(req); err != nil {
		return err
	}

	task, err := NewTaskIssue(req)
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
