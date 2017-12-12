package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/labstack/gommon/log"
)

// Storage is a backend for storing metadata that uses the Registry V2 API
type Storage struct {
	username string
	password string
	verbose  bool
	registry *V2
}

// NewStorage returns a metadata storage backend using a Registry
func NewStorage(username, password string, verbose bool) *Storage {
	return &Storage{
		username: username,
		password: password,
		verbose:  verbose,
	}
}

// GetMetadata returns the data stored for this image with this metadata type
func (s *Storage) GetMetadata(name string, metadata string) (data []byte, imageName string, err error) {
	registryURL, repoName, imageName, repoNameNoHost, _, imageDigest := getNameComponents(name)
	metadataImageName := imageNameForManifest(repoName)

	// Get the digest for the image
	if imageDigest == "" {
		imageDigest, err = s.dockerGetDigest(imageName)
		if err != nil {
			err = fmt.Errorf("image '%s' not found: %v", imageName, err)
			return
		}
	}

	log.Debugf("Image has digest %s", imageDigest)

	// Get the metadata manifest for this image
	raw, err := s.dockerGetData(metadataImageName)
	if err != nil {
		fmt.Printf("No manifesto data stored for image '%s'", imageName)
		os.Exit(1)
	}
	var mml MetadataManifestoList
	json.Unmarshal(raw, &mml)
	log.Debug("Repo metadata index retrieved")

	// We'll need the registry API from here on
	r, err := New(registryURL, s.username, s.password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error connecting to registry: %v\n", err)
		os.Exit(1)
	}

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
						contents, err = s.dockerGetData(repoName + "@" + m.Digest)
						if err != nil {
							fmt.Printf("Couldn't find %s data from manifesto: %v\n", metadata, err)
							os.Exit(1)
						}
					}

					// We should have found the data so we may as well quit now
					return contents, imageName, nil
				}
			}
		}
	}
	return []byte{}, imageName, nil
}

// ListMetadata lists the types of metadata currently stored for this image
func (s *Storage) ListMetadata(image string) (metadataTypes []string, imageName string, err error) {
	_, repoName, imageName, _, _, imageDigest := getNameComponents(image)

	metadataImageName := imageNameForManifest(repoName)

	// Get the digest for the image
	if imageDigest == "" {
		imageDigest, err = s.dockerGetDigest(imageName)
		if err != nil {
			fmt.Printf("Image '%s' not found: %v\n", imageName, err)
			os.Exit(1)
		}
	}

	log.Debugf("Image has digest %s", imageDigest)

	// Get the manifesto data for this repo
	raw, err := s.dockerGetData(metadataImageName)
	if err != nil {
		fmt.Printf("No manifesto data stored for image '%s'\n", imageName)
		log.Debugf("%v", err)
		os.Exit(1)
	}
	var mml MetadataManifestoList
	json.Unmarshal(raw, &mml)

	log.Debugf("Metadata index: %v", mml)

	for _, v := range mml.Images {
		if v.ImageDigest == imageDigest {
			fmt.Printf("Metadata types stored for image '%s':\n", imageName)
			for _, m := range v.MetadataManifesto {
				metadataTypes = append(metadataTypes, m.Type)
			}
		}
	}

	return
}

// PutMetadata stores metadata under a type for an image
func (s *Storage) PutMetadata(image string, metadata string, datafile string) (imageName string, err error) {
	f, err := os.Open(datafile)
	if err != nil {
		return "", fmt.Errorf("error opening file %s: %v", datafile, err)
	}

	registryURL, repoName, imageName, repoNameNoHost, _, imageDigest := getNameComponents(image)
	metadataImageName := imageNameForManifest(repoName)

	// Get the digest for this image
	if imageDigest == "" {
		imageDigest, err = s.dockerGetDigest(imageName)
		if err != nil {
			return imageName, fmt.Errorf("image '%s' not found: %v", imageName, err)
		}
	}

	log.Debugf("Image has digest %s", imageDigest)

	// We'll need the registry API from here on
	r, err := New(registryURL, s.username, s.password)
	if err != nil {
		return imageName, fmt.Errorf("error connecting to registry: %v", err)
	}

	// Store the piece of metadata we've been given
	digest, err := r.UploadBlob(repoNameNoHost, f)
	if err != nil {
		return imageName, fmt.Errorf("error uploading metadata to registry: %v", err)
	}

	fmt.Printf("Metadata '%s' for image '%s' stored at %s\n", metadata, imageName, digest)

	// Read the current manifesto if it exists
	var mml MetadataManifestoList
	raw, err := s.dockerGetData(metadataImageName)
	if err != nil {
		fmt.Printf("Creating new manifesto for %s\n", repoName)
	} else {
		json.Unmarshal(raw, &mml)
	}

	replaced := false
	found := false
	for k, v := range mml.Images {
		if v.ImageDigest == imageDigest {
			found = true
			for kk, m := range v.MetadataManifesto {
				if m.Type == metadata {
					// Replace this with the new blob
					fmt.Printf("Updating '%s' metadata in manifesto for '%s'\n", metadata, imageName)
					mml.Images[k].MetadataManifesto[kk].Digest = digest
					replaced = true
				}
			}

			// A new piece of metadata for this image
			if !replaced {
				fmt.Printf("Adding '%s' metadata to manifesto for '%s'\n", metadata, imageName)
				newMetadata := MetadataManifesto{
					Type:   metadata,
					Digest: digest,
				}
				mml.Images[k].MetadataManifesto = append(mml.Images[k].MetadataManifesto, newMetadata)
			}
		}
	}

	// Metadata for a new image
	if !found {
		fmt.Printf("Adding '%s' metadata to manifesto for '%s'\n", metadata, imageName)
		newImm := ImageMetadataManifesto{
			ImageDigest: imageDigest,
			MetadataManifesto: []MetadataManifesto{
				{
					Type:   metadata,
					Digest: digest,
				},
			},
		}
		mml.Images = append(mml.Images, newImm)
	}

	// Write the manifesto file
	data, err := json.Marshal(mml)
	if err != nil {
		return imageName, fmt.Errorf("couldn't marshal manifesto data: %v", err)
	}

	err = ioutil.WriteFile(tempFileName, []byte(data), 0644)
	if err != nil {
		return imageName, fmt.Errorf("couldn't write temporary manifesto file: %v", err)
	}

	// Store the manifesto file in the registry
	s.dockerPutData(metadataImageName, "manifesto", tempFileName)
	err = os.Remove(tempFileName)
	if err != nil {
		return imageName, fmt.Errorf("couldn't remove temporary manifesto file: %v", err)
	}

	return
}

func (s *Storage) dockerGetDigest(imageName string) (digest string, err error) {
	// Make sure we have an up-to-date version of this image
	s.execCommand("docker", "pull", imageName)
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

func (s *Storage) dockerGetData(imageName string) ([]byte, error) {
	err := s.execCommand("docker", "pull", imageName)
	if err != nil {
		return []byte{}, err
	}

	s.execCommand("docker", "create", "--name="+tempContainerName, imageName, "x")
	s.execCommand("docker", "cp", tempContainerName+":/data", tempFileName)
	s.execCommand("docker", append([]string{"rm"}, tempContainerName)...)
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

// imageName is the name we'll store this data under, including the tag e.g. myorg/myrepo:mytag or myorg/myrepo@sha256:12345...
// datafile is the name of the file we get the data from
func (s *Storage) dockerPutData(imageName string, metadataName string, datafile string) (string, error) {
	// Copy file locally so that it's going to be in the build context
	metadata, err := os.Open(datafile)
	if err != nil {
		return "", fmt.Errorf("couldn't open file %s: %v", datafile, err)
	}

	defer metadata.Close()
	tf, err := ioutil.TempFile(".", "metadata")
	if err != nil {
		return "", fmt.Errorf("error creating temporary file: %v", err)
	}

	_, err = io.Copy(tf, metadata)
	if err != nil {
		return "", fmt.Errorf("error copying to temporary file: %v", err)
	}

	if err = tf.Close(); err != nil {
		os.Remove(tf.Name())
		return "", fmt.Errorf("error closing temporary file: %v", err)
	}

	df, err := ioutil.TempFile(".", "Dockerfile")
	dockerfile := fmt.Sprintf("FROM scratch \nADD %s /data\n", tf.Name())
	_, err = df.Write([]byte(dockerfile))
	if err != nil {
		return "", fmt.Errorf("couldn't create Dockerfile: %v", err)
	}

	s.execCommand("docker", "build", "-f", df.Name(), "-t", imageName, ".")

	// Delete the Dockerfile and the temporary file
	err = os.Remove(df.Name())
	if err != nil {
		return "", fmt.Errorf("couldn't delete Dockerfile: %v", err)
	}

	err = os.Remove(tf.Name())
	if err != nil {
		return "", fmt.Errorf("couldn't delete temporary file: %v", err)
	}

	s.execCommand("docker", "push", imageName)

	digest, err := s.dockerGetDigest(imageName)
	if err != nil {
		return "", fmt.Errorf("couldn't get digest: %v", err)
	}

	return digest, nil
}

func (s *Storage) execCommand(name string, arg ...string) error {
	ex := exec.Command(name, arg...)
	ex.Stdin = os.Stdin
	ex.Stderr = os.Stderr
	if s.verbose {
		ex.Stdout = os.Stdout
	}
	return ex.Run()
}
