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

	"github.com/spf13/cobra"
)

type Stream struct {
	Stream string `json:"stream"`
}

// putCmd stores manifesto data for this image
var putCmd = &cobra.Command{
	Use:   "put [IMAGE] [metadata] [data]",
	Short: "Put metadata for the container image",
	Long: `Store data as metadata associated with the image. 
	For Grafeas proof-of-concept support
	 - the data field is a directory, containing a notes and occurrences directory, each containing JSON files
	 - the only supported metadata type is PACKAGE_VULNERABILITY`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		if len(args) < 3 {
			cmd.Help()
			return
		}

		name := args[0]
		metadataName := args[1]
		datafile := args[2]

		imageName, err := storageBackend.PutMetadata(name, metadataName, datafile)
		if err != nil {
			fmt.Printf("Error putting metadata for image %s: %v\n", imageName, err)
			os.Exit(1)
		}
	},
}
