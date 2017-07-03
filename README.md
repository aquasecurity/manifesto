# manifesto
Use Manifesto to store and query metadata for Docker images. This metadata could be information that you want to store about an image *post-build* - so labels are not sufficient. 

Examples of the kind of information you might want to store post-build include: 

* contact information for this image
* seccomp profile
* QA or other approvals for this image. 

The intention is that each piece of metadata could be signed using Notary.

At the moment this is a Proof of Concept - feedback and ideas very welcome. 

## Installation

Clone this repo (or go get aquasecurity/manifesto)
Go to the directory and `go build .`

## Usage

```
$ ./manifesto --help
Inspect your containers and container images

Usage:
  manifesto [command]

Available Commands:
  get         Show metadata for the container image
  help        Help about any command
  list        List currently stored metadata for the container image
  put         Put metadata for the container image
```

By default (like Docker images) manifesto assumes the 'latest' tag if a tag is not given. 

### Example

```
$ ./manifesto put lizrice/imagetest something ~/temp.json
Storing metadata 'something' for 'lizrice/imagetest:latest'
Metadata 'something' for 'lizrice/imagetest:latest' stored at sha256:7be34480285971f16eed284b13fa7d417649f18c7d1af9b2de6970ce99e3cbbd
Updating manifesto for lizrice/imagetest
Replacing 'something' metadata in manifesto for 'lizrice/imagetest:latest'

$ ./manifesto list lizrice/imagetest
Metadata types stored for image 'lizrice/imagetest:latest':
    something

$ ./manifesto get lizrice/imagetest something
{
  "key" : "value",
  "createdBy" : "liz",
  "number" : 56
}
```

# Proof of concept status

In this proof of concept:  

* we store arbitrary metadata within the Docker registry 
* we store a "manifest" for the repository with the fixed tag "_manifest"
* the manifest is a json file with references to all the metadata stored for this repository

# To Do's 

* The manifest file should refer to images by SHA rather than by tag (as the tag can move around). Storing metadata against a particular tag should store it against the SHA currently referred to by that tag. 
* Metadata is currently pushed to a new image tagged (for example) `myorg/myimage:_manifest_<metadata type>`. It would be better to push it directly to a blob. 
* Add data signing capabilities. 
* Code currently execs out to the docker client executable - would be better to use the go client and call the API directly. 
