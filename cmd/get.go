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

// MetadataManifesto gives the type of a piece of arbitrary manifesto data, and the digest where it can be found
// A given image can only have one current piece of data of each type.
// Example types might include: "seccomp", "approvals", "contact"
type MetadataManifesto struct {
	Type   string `json:"type"`
	Digest string `json:"digest"`
}

// ImageMetadataManifesto associates a piece of manifesto data with a particular image
type ImageMetadataManifesto struct {
	ImageDigest       string              `json:"image_digest"`
	MetadataManifesto []MetadataManifesto `json:"manifesto"`
}

// MetadataManifestoList holds all the metadata for a given image repository
type MetadataManifestoList struct {
	Images []ImageMetadataManifesto `json:"images"`
}

// getCmd gets manifesto data
var getCmd = &cobra.Command{
	Use:   "get [IMAGE] [metadata]",
	Short: "Show metadata for the container image",
	Long:  `Display metadata information about the container image.`,
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		if len(args) < 2 {
			cmd.Help()
			return
		}

		metadata := args[1]
		data, imageName, err := storageBackend.GetMetadata(args[0], metadata)
		if err != nil {
			fmt.Printf("Error getting metadata for image %s: %v\n", imageName, err)
			os.Exit(1)
		}
		if len(data) == 0 {
			fmt.Printf("Could not find '%s' metadata for image '%s'\n", metadata, imageName)
			os.Exit(0)
		}

		fmt.Printf("%s\n", string(data))
	},
}
