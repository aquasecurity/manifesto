// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/aquasecurity/manifesto/grafeas"
	"github.com/aquasecurity/manifesto/registry"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type metadataStorage interface {
	GetMetadata(image string, metadata string) ([]byte, string, error)
	ListMetadata(image string) ([]string, string, error)
	PutMetadata(image string, metadata string, data string) (string, error)
}

var (
	username       string
	password       string
	storage        string
	verbose        bool
	grafeasURL     string
	grafeasProjID  string
	storageBackend metadataStorage
	log            = logging.MustGetLogger("")
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "manifesto",
	Short: "Manage metadata associated with your container images",
	Long: `Store, retrieve and list pieces of metadata about your container images.
Storage options: 
- store in the container registry alongside your images 
- use the Grafeas API
This tool is currently a proof-of-concept so please expect changes.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports Persistent Flags, which, if defined here,
	// will be global for your application.

	RootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "Registry username (can also be passed in with the env var REGISTRY_USERNAME)")
	RootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Registry password (can also be passed in with the env var REGISTRY_PASSWORD)")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Send debug output to stderr")

	RootCmd.PersistentFlags().StringVarP(&storage, "storage", "s", "", "Storage type to use (default is 'registry', also supported: 'grafeas'")

	RootCmd.PersistentFlags().StringVarP(&grafeasURL, "grafeas_url", "", "http://grafeas:8080", "URL of Grafeas server (only used if storage type is grafeas)")
	RootCmd.PersistentFlags().StringVarP(&grafeasProjID, "grafeas_proj_id", "", "", "Grafeas project ID (only used if storage type is grafeas). This would typically be a customer project name.")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

	RootCmd.AddCommand(getCmd)
	RootCmd.AddCommand(listCmd)
	RootCmd.AddCommand(putCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigName(".manifesto") // name of config file (without extension)
	viper.AddConfigPath(".")          // adding current directory as first search path
	viper.AddConfigPath("$HOME")      // adding home directory

	viper.BindEnv("username", "REGISTRY_USERNAME")
	viper.BindEnv("password", "REGISTRY_PASSWORD")
	viper.BindEnv("storage", "MANIFESTO_STORAGE")
	viper.BindEnv("verbose", "MANIFESTO_VERBOSE")
	viper.BindEnv("grafeas_url", "GRAFEAS_URL")
	viper.BindEnv("grafeas_proj_id", "GRAFEAS_PROJ_ID")

	viper.AutomaticEnv() // read in environment variables that match

	viper.BindPFlag("username", RootCmd.Flags().Lookup("username"))
	viper.BindPFlag("password", RootCmd.Flags().Lookup("password"))
	viper.BindPFlag("storage", RootCmd.Flags().Lookup("storage"))
	viper.BindPFlag("verbose", RootCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("grafeas_url", RootCmd.Flags().Lookup("grafeas_url"))
	viper.BindPFlag("grafeas_proj_id", RootCmd.Flags().Lookup("grafeas_proj_id"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Debugf("Using config file %s", viper.ConfigFileUsed())
	}

	username = viper.GetString("username")
	password = viper.GetString("password")
	verbose = viper.GetBool("verbose")

	storage = viper.GetString("storage")
	grafeasURL = viper.GetString("grafeas_url")
	grafeasProjID = viper.GetString("grafeas_proj_id")

	// Set up logging
	if verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	// Backend storage type
	switch storage {
	case "grafeas":
		if grafeasProjID == "" {
			fmt.Println("You need to specify a Grafeas project ID")
			os.Exit(1)
		}
		storageBackend = grafeas.NewStorage(grafeasURL, grafeasProjID, verbose)
	default:
		log.Debug("Registry storage")
		storageBackend = registry.NewStorage(username, password, verbose)
	}
}
