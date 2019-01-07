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
	"golang.org/x/net/websocket"
	"net/http"
)

type chanWriter struct {
	ch chan byte
}

func newChanWriter() *chanWriter {
	return &chanWriter{make(chan byte, 1024)}
}

func (w *chanWriter) Chan() <-chan byte {
	return w.ch
}

func (w *chanWriter) Write(p []byte) (int, error) {
	n := 0
	for _, b := range p {
		w.ch <- b
		n++
	}
	return n, nil
}

func (w *chanWriter) Close() error {
	close(w.ch)
	return nil
}

// Represents interface to which each task type must conform
type task interface {
	TaskType() string
	GetOutput() chanWriter
	Run()
}

// Ensure each task type conforms to the task interface
var (
	_ task = (*taskIssue)(nil)
)

var taskStore = make(map[uuid.UUID]task)

func GetTasks(c echo.Context) error {
	var resp []task
	for _, task := range taskStore {
		resp = append(resp, task)
	}

	if resp == nil {
		// Return an empty array instead of nil
		resp = make([]task, 0)
	}

	return c.JSON(http.StatusOK, resp)
}

func GetTask(c echo.Context) error {
	rawTaskId := c.Param("id")

	taskId, err := uuid.Parse(rawTaskId)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	task, ok := taskStore[taskId]
	if !ok {
		return c.NoContent(http.StatusNotFound)
	}

	return c.JSON(http.StatusOK, task)
}

func GetTaskLog(c echo.Context) error {
	rawTaskId := c.Param("id")
	taskId, err := uuid.Parse(rawTaskId)
	if err != nil {
		return c.NoContent(http.StatusNotFound)
	}

	task, ok := taskStore[taskId]
	if !ok {
		return c.NoContent(http.StatusNotFound)
	}

	websocket.Handler(func(ws *websocket.Conn) {
		defer func() {
			// Swallow any errors
			_ = ws.Close()
		}()

		c.Logger().Info(fmt.Sprintf("WebSocket connected: %s", c.Request().RequestURI))

		output := task.GetOutput()
		for msg := range output.Chan() {
			err := websocket.Message.Send(ws, msg)
			if err != nil {
				c.Logger().Error(err)
				break
			}
		}
	}).ServeHTTP(c.Response(), c.Request())

	return nil
}
