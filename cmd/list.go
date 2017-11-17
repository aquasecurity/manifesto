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

// listCmd gets a list of available manifesto data for this image
var listCmd = &cobra.Command{
	Use:   "list [IMAGE]",
	Short: "List currently stored metadata for the container image",
	Long:  `Display a list of the metadata stored for the specified container image.`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error
		if len(args) < 1 {
			cmd.Help()
			return
		}

		metadataTypes, imageName, err := storageBackend.ListMetadata(args[0])
		if err != nil {
			fmt.Printf(err.Error())
			os.Exit(1)
		}

		if len(metadataTypes) == 0 {
			fmt.Printf("No metadata stored for image '%s'\n", imageName)
		}

		for _, v := range metadataTypes {
			fmt.Printf("    %s\n", v)
		}
	},
}
