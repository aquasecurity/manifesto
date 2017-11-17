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
	"io"
	"os"

	"github.com/aquasecurity/manifesto/registry"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type metadataStorage interface {
	GetMetadata(image string, metadata string) ([]byte, string, error)
	ListMetadata(image string) ([]string, string, error)
	PutMetadata(image string, metadata string, data io.Reader) (string, error)
}

var (
	username       string
	password       string
	storage        string
	verbose        bool
	storageBackend metadataStorage
	log            = logging.MustGetLogger("")
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "manifesto",
	Short: "Manage metadata associated with your container images",
	Long: `Store, retrieve and list pieces of metadata alongside your container images in the registry. 
Metadata is associated with specific images (by hash).
	`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
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

	RootCmd.PersistentFlags().StringVarP(&storage, "storage", "s", "", "Storage type to use")

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

	viper.AutomaticEnv() // read in environment variables that match

	viper.BindPFlag("username", RootCmd.Flags().Lookup("username"))
	viper.BindPFlag("password", RootCmd.Flags().Lookup("password"))
	viper.BindPFlag("storage", RootCmd.Flags().Lookup("storage"))
	viper.BindPFlag("verbose", RootCmd.Flags().Lookup("verbose"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Debugf("Using config file %s", viper.ConfigFileUsed())
	}

	username = viper.GetString("username")
	password = viper.GetString("password")
	verbose = viper.GetBool("verbose")

	storage = viper.GetString("storage")

	// Set up logging
	if verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	// Backend storage type
	switch storage {
	default:
		log.Debug("Registry storage")
		storageBackend = registry.NewStorage(username, password, verbose)
	}
}
