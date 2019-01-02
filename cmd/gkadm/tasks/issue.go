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
	"fmt"
	"github.com/google/uuid"
	"github.com/labstack/echo"
	"net/http"
	"time"
)

const taskTypeIssue = "issue"

type issueRequest struct {
	SystemSecret string              `json:"systemSecret"`
	Realms       []issueRequestRealm `json:"realms"`
}

type issueRequestRealm struct {
	Name      string    `json:"name"`
	Slot      int       `json:"slot"`
	UUID      uuid.UUID `json:"UUID"`
	AuthKey   string    `json:"authKey"`
	ReadKey   string    `json:"readKey"`
	UpdateKey string    `json:"updateKey"`
}

type taskIssue struct {
	ID      uuid.UUID     `json:"id"`
	Type    string        `json:"type"`
	Request *issueRequest `json:"-"`
	Log     chan string   `json:"-"`
}

func (m *taskIssue) TaskType() string {
	return taskTypeIssue
}

func (m *taskIssue) GetLog() chan string {
	return m.Log
}

func (m *taskIssue) Run() {
	iters := 1
	timer := time.NewTimer(time.Second)

	for {
		<-timer.C
		m.Log <- fmt.Sprintf("%d seconds have passed", iters)
		iters++

		if iters > 10 {
			close(m.Log)
			break
		} else {
			timer.Reset(time.Second)
		}
	}

}

func NewTaskIssue(request *issueRequest) (*taskIssue, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	return &taskIssue{
		ID:      id,
		Type:    taskTypeIssue,
		Request: request,
		Log:     make(chan string, 50),
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
