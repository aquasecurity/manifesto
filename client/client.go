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

package client

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	docker "github.com/docker/docker/client"
)

// DockerClient is our local version of the docker client so we can add some new methods
type DockerClient struct {
	*docker.Client
}

// NewDockerClient returns a Docker client
func NewDockerClient() (*DockerClient, error) {
	c, err := docker.NewEnvClient()
	return &DockerClient{c}, err
}

// ImageExecute starts a container for this image and executes the specified command
func (c *DockerClient) ImageExecute(name string, cmd []string) (length int64, err error) {
	config := container.Config{
		Image: name,
		Cmd:   cmd,
	}

	resp, err := c.ContainerCreate(context.Background(), &config, nil, nil, "")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = c.ContainerStart(context.Background(), resp.ID, types.ContainerStartOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}

	_, errChan := c.ContainerWait(context.Background(), resp.ID, container.WaitConditionNotRunning)
	err = <-errChan
	if err != nil {
		fmt.Println(err)
		return
	}

	out, err := c.ContainerLogs(context.Background(), resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		fmt.Println(err)
		return
	}

	return io.Copy(os.Stdout, out)
}

// GetLabel gets a named label from a container or container image
func (c *DockerClient) GetLabel(name string, labelKey string) (labelValue string, isContainer bool, err error) {
	var containerJSON types.ContainerJSON
	var imageJSON types.ImageInspect
	var labels map[string]string

	containerJSON, err = c.ContainerInspect(context.Background(), name)
	if err != nil && docker.IsErrContainerNotFound(err) {
		imageJSON, _, err = c.ImageInspectWithRaw(context.Background(), name)
		if err != nil {
			return
		}

		isContainer = false
		labels = imageJSON.Config.Labels

	} else {
		isContainer = true
		labels = containerJSON.Config.Labels
	}

	labelValue, _ = labels[labelKey]
	return
}
