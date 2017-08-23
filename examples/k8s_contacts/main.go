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

// This example code shows how to use a Kubernetes annotation to generate
// a Slack alert.
// The annotation is expected be called "contact" and contain a JSON struct:
//
// {
//   "slack": "<Slack webhook URL>",
//   "slack_channel": "<Slack channel name>" (optional)
// }
//
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	slack "github.com/ashwanthkumar/slack-go-webhook"
)

type Contact struct {
	Slack        string
	SlackChannel string `json:"slack_channel"`
}

func main() {
	component := os.Args[1]
	channel := "#general"

	cmd := exec.Command("kubectl", "get", "deployment", component, "-o=custom-columns=:.metadata.annotations.contact", "--no-headers")
	out, _ := cmd.Output()

	var contact Contact
	err := json.Unmarshal(out, &contact)
	if err != nil {
		panic(err)
	}

	if contact.Slack == "" {
		fmt.Println("No Slack channel found")
		os.Exit(1)
	}

	if contact.SlackChannel != "" {
		channel = contact.SlackChannel
	}

	payload := slack.Payload{
		Channel:   channel,
		Text:      "Hey, " + component + " needs your help",
		Username:  "Kubebot",
		IconEmoji: ":kubernetes:",
	}

	errs := slack.Send(contact.Slack, "", payload)
	if len(errs) > 0 {
		fmt.Printf("error: %s\n", errs)
	}
}
