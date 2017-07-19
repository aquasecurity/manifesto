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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

const tempFileName = "_manifesto.out"
const tempContainerName = "manifesto.temp"

// MetadataManifesto gives the type of a piece of arbitrary manifesto data, and the digest where it can be found
// A given image can only have one current piece of data of each type.
// Example types might include: "seccomp", "approvals", "contact"
type MetadataManifesto struct {
	Type   string `json:"type"`
	Digest string `json:"digest"`
}

// MetadataManifestoTag associates a piece of manifesto data with a particular tagged version of the image
type ImageMetadataManifesto struct {
	ImageDigest       string              `json:"image_digest"`
	MetadataManifesto []MetadataManifesto `json:"manifesto"`
}

// MetadataManifestoList holds all the metadata for a given image repository
type MetadataManifestoList struct {
	Images []ImageMetadataManifesto `json:"images"`
}

func dockerGetData(imageName string) ([]byte, error) {
	ex := exec.Command("docker", "pull", imageName)
	ex.Run()
	ex = exec.Command("docker", "create", "--name="+tempContainerName, imageName, "x")
	ex.Run()
	ex = exec.Command("docker", "cp", tempContainerName+":/data", tempFileName)
	ex.Run()
	ex = exec.Command("docker", append([]string{"rm"}, tempContainerName)...)
	ex.Run()
	raw, err := ioutil.ReadFile(tempFileName)
	if err != nil {
		return raw, err
	}
	err = os.Remove(tempFileName)
	if err != nil {
		fmt.Printf("%v\n", err)
	}

	return raw, err
}

func dockerGetDigest(imageName string) (digest string, err error) {
	// Make sure we have an up-to-date version of this image
	ex := exec.Command("docker", "pull", imageName)
	ex.Run()

	ex = exec.Command("docker", "inspect", imageName, "-f", "{{.RepoDigests}}")
	digestOut, err := ex.Output()
	if err != nil {
		return "", fmt.Errorf("error reading inspect output: %v", err)
	}

	hh := strings.Split(string(digestOut), "@")
	if len(hh) < 2 {
		return "", fmt.Errorf("digest not found in %s", digestOut)
	}

	digest = strings.TrimSpace(hh[1])
	digest = strings.TrimRight(digest, "]")
	return digest, nil
}

func imageNameForManifest(imageName string) string {
	return imageName + ":_manifesto"
}

func repoAndTaggedNames(name string) (repoName string, imageName string, tagName string) {
	nameSlice := strings.Split(name, ":")
	repoName = nameSlice[0]
	tagName = "latest"
	if len(nameSlice) > 1 {
		tagName = nameSlice[1]
	}
	imageName = repoName + ":" + tagName
	return repoName, imageName, tagName
}

// getCmd gets manifesto data
var getCmd = &cobra.Command{
	Use:   "get [IMAGE] [metadata]",
	Short: "Show metadata for the container image",
	Long:  `Display metadata information about the container image.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 2 {
			cmd.Help()
			return
		}

		name := args[0]
		metadata := args[1]

		repoName, imageName, _ := repoAndTaggedNames(name)
		metadataImageName := imageNameForManifest(repoName)

		// Get the digest for the image
		imageDigest, err := dockerGetDigest(imageName)
		if err != nil {
			fmt.Printf("Image '%s' not found\n", imageName)
			os.Exit(1)
		}

		// fmt.Printf("Image %s has digest %s\n", imageName, imageDigest)

		// Get the metadata manifest for this image
		raw, err := dockerGetData(metadataImageName)
		if err != nil {
			fmt.Printf("No manifesto data stored for image '%s'\n", imageName)
			os.Exit(1)
		}
		var mml MetadataManifestoList
		json.Unmarshal(raw, &mml)

		found := false
		for _, v := range mml.Images {
			if v.ImageDigest == imageDigest {
				// fmt.Printf("Found metadata for %v\n", imageName)
				for _, m := range v.MetadataManifesto {
					if m.Type == metadata {
						// fmt.Printf("%v\n", m.Digest)
						// TODO!! These should go directly into blobs rather than into their own image
						contents, err := dockerGetData(repoName + "@" + m.Digest)
						if err != nil {
							fmt.Printf("Couldn't find %s data from manifesto: %v\n", metadata, err)
							os.Exit(1)
						}

						fmt.Printf("%s\n", string(contents))
						found = true
					}
				}
			}
		}

		if !found {
			fmt.Printf("Could not find '%s' metadata for image '%s'\n", metadata, imageName)
		}
	},
}

func init() {
	RootCmd.AddCommand(getCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
