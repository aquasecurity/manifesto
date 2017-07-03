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
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

type Stream struct {
	Stream string `json:"stream"`
}

// imageName is the name we'll store this data under, including the tag e.g. myorg/myrepo:mytag or myorg/myrepo@sha256:12345...
// datafile is the name of the file we get the data from
func dockerPutData(imageName string, metadataName string, datafile string) string {
	// Copy file locally so that it's going to be in the build context
	metadata, err := os.Open(datafile)
	if err != nil {
		fmt.Printf("Couldn't open file %s: %v\n", datafile, err)
		os.Exit(1)
	}

	defer metadata.Close()
	tf, err := ioutil.TempFile(".", "metadata")
	if err != nil {
		fmt.Printf("Error creating temporary file: %v\n", err)
		os.Exit(1)
	}

	_, err = io.Copy(tf, metadata)
	if err != nil {
		fmt.Printf("Error copying to temporary file: %v\n", err)
		os.Exit(1)
	}

	if err = tf.Close(); err != nil {
		fmt.Printf("Error closing temporary file: %v\n", err)
		os.Remove(tf.Name())
		os.Exit(1)
	}

	df, err := ioutil.TempFile(".", "Dockerfile")
	dockerfile := fmt.Sprintf("FROM scratch \nADD %s /data\n", tf.Name())
	_, err = df.Write([]byte(dockerfile))
	if err != nil {
		fmt.Printf("could not create Dockerfile: %v\n", err)
		os.Exit(1)
	}

	ex := exec.Command("docker", "build", "-f", df.Name(), "-t", imageName, ".")
	// ex.Stderr = os.Stderr
	// ex.Stdout = os.Stdout
	ex.Run()

	// Delete the Dockerfile and the temporary file
	err = os.Remove(df.Name())
	if err != nil {
		fmt.Printf("Couldn't delete Dockerfile: %v\n", err)
		os.Exit(1)
	}

	err = os.Remove(tf.Name())
	if err != nil {
		fmt.Printf("Couldn't delete temp file: %v\n", err)
		os.Exit(1)
	}

	ex = exec.Command("docker", "push", imageName)
	// ex.Stderr = os.Stderr
	// ex.Stdout = os.Stdout
	ex.Run()
	ex = exec.Command("docker", "inspect", imageName, "-f", "{{.RepoDigests}}")
	digestOut, err := ex.Output()
	if err != nil {
		fmt.Printf("Error reading inspect output: %v\n", err)
		os.Exit(1)
	}
	hh := strings.Split(string(digestOut), "@")
	if len(hh) < 2 {
		fmt.Printf("Digest not found in %s\n", digestOut)
		os.Exit(1)
	}

	digest := strings.TrimSpace(hh[1])
	digest = strings.TrimRight(digest, "]")
	return digest
}

// putCmd represents the cve command
var putCmd = &cobra.Command{
	Use:   "put [IMAGE] [metadata] [datafile]",
	Short: "Put metadata for the container image",
	Long:  `Store datafile as metadata associated with the image`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 3 {
			cmd.Help()
			return
		}

		name := args[0]
		metadataName := args[1]
		datafile := args[2]

		repoName, imageName := repoAndTaggedNames(name)
		metadataImageName := imageNameForManifest(repoName)

		// Store the piece of metadata we've been given
		// TODO!! Should check that the image exists before adding metadata for it
		// TODO!! These should go directly into blobs rather than into their own image
		fmt.Printf("Storing metadata '%s' for '%s'\n", metadataName, imageName)
		digest := dockerPutData(repoName+":_manifest_"+metadataName, metadataName, datafile)
		fmt.Printf("Metadata '%s' for '%s' stored at %s\n", metadataName, imageName, digest)

		// Read the current manifesto if it exists
		var mml MetadataManifestList
		raw, err := dockerGetData(metadataImageName)
		if err != nil {
			fmt.Printf("Creating new manifesto for %s\n", repoName)
		} else {
			fmt.Printf("Updating manifesto for %s\n", repoName)
			json.Unmarshal(raw, &mml)
		}

		replaced := false
		found := false
		for k, v := range mml.Tags {
			// TODO!! This should be checking for images by SHA not by tag as these can move
			if v.Tag == imageName {
				found = true
				for kk, m := range v.MetadataManifest {
					if m.Type == metadataName {
						// Replace this with the new blob
						fmt.Printf("Updating '%s' metadata in manifesto for '%s'\n", metadataName, imageName)
						mml.Tags[k].MetadataManifest[kk].Digest = digest
						replaced = true
					}
				}

				// A new piece of metadata for this image
				if !replaced {
					fmt.Printf("Adding '%s' metadata to manifesto for '%s'\n", metadataName, imageName)
					newTag := MetadataManifest{
						Type:   metadataName,
						Digest: digest,
					}
					mml.Tags[k].MetadataManifest = append(mml.Tags[k].MetadataManifest, newTag)
				}
			}
		}

		// Metadata for a new image
		if !found {
			fmt.Printf("Adding '%s' metadata to new manifesto for '%s'\n", metadataName, imageName)
			newMMT := MetadataManifestTag{
				Tag: imageName,
				MetadataManifest: []MetadataManifest{
					{
						Type:   metadataName,
						Digest: digest,
					},
				},
			}
			mml.Tags = append(mml.Tags, newMMT)
			// fmt.Printf("%#v\n", newMMT)
		}

		// fmt.Printf("Updated manifesto: %v\n", mml)

		// Write the manifesto file
		data, err := json.Marshal(mml)
		if err != nil {
			fmt.Printf("Couldn't marshal the manifesto data file: %v\n", err)
			os.Exit(1)
		}

		err = ioutil.WriteFile(tempFileName, []byte(data), 0644)
		if err != nil {
			fmt.Printf("Couldn't write the manifesto data file: %v\n", err)
			os.Exit(1)
		}

		dockerPutData(metadataImageName, "manifest", tempFileName)
		err = os.Remove(tempFileName)
		if err != nil {
			fmt.Printf("Couldn't remove file: %v\n", err)
		}
	},
}

func init() {
	RootCmd.AddCommand(putCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// cveCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}
