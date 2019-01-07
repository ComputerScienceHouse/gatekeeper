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
	"fmt"
	"github.com/ComputerScienceHouse/gatekeeper/cmd/gkadm/tasks"
	"github.com/ComputerScienceHouse/gatekeeper/device"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/labstack/gommon/log"
	"github.com/spf13/cobra"
	"net/http"
	"os"
	"runtime"
)

var (
	version    = "devel"
	buildDate  string
	commitHash string
)

func serve() {
	e := echo.New()

	// Configuration
	e.Logger.SetLevel(log.INFO)
	e.HideBanner = true
	e.Logger.SetHeader("[${time_rfc3339}] [${level}]")

	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "[${time_rfc3339}] ${method} ${uri} (${status})\n",
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{
			"https://gatekeeper.csh.rit.edu",
			"http://localhost:3000",
		},
		AllowMethods: []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPut,
			http.MethodPatch,
			http.MethodPost,
			http.MethodDelete,
		},
	}))

	/*
	  Routes
	*/
	e.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, "<h2>Gatekeeper Admin Helper</h2>\n<p>Please visit your instance's admin dashboard to interact with this application.</p>")
	})

	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	e.GET("/healthz/nfc", func(c echo.Context) error {
		if device.NFCHealthz() {
			return c.String(http.StatusOK, "ok")
		} else {
			return c.NoContent(http.StatusServiceUnavailable)
		}
	})

	e.GET("/tasks", tasks.GetTasks)
	e.GET("/tasks/:id", tasks.GetTask)
	e.GET("/tasks/:id/log", tasks.GetTaskLog)
	e.POST("/issue", tasks.CreateIssueTask)

	// Start the server
	e.Logger.Fatal(e.Start(":42069"))
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gkadm",
		Short: "Gatekeeper Admin",
		Long:  `The Gatekeeper Admin Server`,
		Run: func(cmd *cobra.Command, args []string) {
			serve()
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`gkadm:
 version     : %s
 build date  : %s
 git hash    : %s
 go version  : %s
 go compiler : %s
 platform    : %s/%s
`, version, buildDate, commitHash,
				runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		},
	}

	rootCmd.AddCommand(versionCmd)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
