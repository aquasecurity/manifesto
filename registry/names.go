package registry

import "strings"

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

func imageNameForManifest(imageName string) string {
	return imageName + ":_manifesto"
}
