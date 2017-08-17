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

	"github.com/aquasecurity/manifesto/registry"

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

// ImageMetadataManifesto associates a piece of manifesto data with a particular image
type ImageMetadataManifesto struct {
	ImageDigest       string              `json:"image_digest"`
	MetadataManifesto []MetadataManifesto `json:"manifesto"`
}

// MetadataManifestoList holds all the metadata for a given image repository
type MetadataManifestoList struct {
	Images []ImageMetadataManifesto `json:"images"`
}

func dockerGetData(imageName string) ([]byte, error) {
	err := execCommand("docker", "pull", imageName)
	if err != nil {
		return []byte{}, err
	}

	execCommand("docker", "create", "--name="+tempContainerName, imageName, "x")
	execCommand("docker", "cp", tempContainerName+":/data", tempFileName)
	execCommand("docker", append([]string{"rm"}, tempContainerName)...)
	raw, err := ioutil.ReadFile(tempFileName)
	if err != nil {
		return raw, err
	}
	err = os.Remove(tempFileName)
	if err != nil {
		return raw, err
	}

	return raw, err
}

func dockerGetDigest(imageName string) (digest string, err error) {
	// Make sure we have an up-to-date version of this image
	execCommand("docker", "pull", imageName)
	ex := exec.Command("docker", "inspect", imageName, "-f", "{{.RepoDigests}}")
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

// registryName - dockerHub if omitted
// repoName - hostname/org/repo - hostname is omitted if it's dockerHub
// imageName - hostname/org/repo:tag - latest is used for the tag if not specified; hostname omitted if it's dockerHub
// repoNameNoHost - org/repo - hostname always omitted
func getNameComponents(name string) (registryName string, repoName string, imageName string, repoNameNoHost string, tagName string, digestName string) {

	// reference := name [ ":" tag ] [ "@" digest ]
	nameSlice := strings.Split(name, "@")
	if len(nameSlice) > 1 {
		digestName = nameSlice[1]
		name = nameSlice[0]
	}

	// name := [ hostname "/" ] component [ "/" component ]*
	// name can include : as part of the host name, so we look for hostname and components before
	// looking for the tag
	nameSlice = strings.Split(name, "/")
	registryName = dockerHub
	if len(nameSlice) > 2 {
		name = strings.Join(nameSlice[1:], "/")
		registryName = nameSlice[0]

		// Include registry name in repo name if it's not Docker Hub
		repoName = registryName + "/"
	}

	// Now look for a tag
	nameSlice = strings.Split(name, ":")
	repoName += nameSlice[0]
	repoNameNoHost = nameSlice[0]
	tagName = "latest"
	if len(nameSlice) > 1 {
		tagName = nameSlice[1]
	}

	imageName = repoName + ":" + tagName
	return registryName, repoName, imageName, repoNameNoHost, tagName, digestName
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

		name := args[0]
		metadata := args[1]

		registryURL, repoName, imageName, repoNameNoHost, _, imageDigest := getNameComponents(name)
		metadataImageName := imageNameForManifest(repoName)

		// Get the digest for the image
		if imageDigest == "" {
			imageDigest, err = dockerGetDigest(imageName)
			if err != nil {
				fmt.Printf("Image '%s' not found\n", imageName)
				os.Exit(1)
			}
		}

		log.Debugf("Image has digest %s", imageDigest)

		// Get the metadata manifest for this image
		raw, err := dockerGetData(metadataImageName)
		if err != nil {
			fmt.Printf("No manifesto data stored for image '%s'\n", imageName)
			os.Exit(1)
		}
		var mml MetadataManifestoList
		json.Unmarshal(raw, &mml)
		log.Debug("Repo metadata index retrieved")

		// We'll need the registry API from here on
		ensureRegistryCredentials()
		r, err := registry.New(registryURL, username, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error connecting to registry: %v\n", err)
			os.Exit(1)
		}

		found := false
		for _, v := range mml.Images {
			if v.ImageDigest == imageDigest {
				log.Debug("Image metadata retrieved")
				for _, m := range v.MetadataManifesto {
					if m.Type == metadata {
						log.Debugf("'%s' metadata identified", metadata)
						contents, err := r.GetBlob(repoNameNoHost, m.Digest)
						if err != nil {
							// Maybe this metadata was stored as an image by a previous version of manifesto
							// so try getting it that way
							// TODO!! Retire this one day
							log.Debugf("This metadata may be stored in an image rather than a blob: %v", err)
							contents, err = dockerGetData(repoName + "@" + m.Digest)
							if err != nil {
								fmt.Printf("Couldn't find %s data from manifesto: %v\n", metadata, err)
								os.Exit(1)
							}
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
