# manifesto
Use Manifesto to store and query metadata for Docker images. This metadata can be information that you want to store about an image *post-build* - where labels are not sufficient. 

Examples of the kind of information you might want to store post-build include: 

* contact information for this image
* seccomp profile
* QA or other approvals for this image. 

Although we haven't yet implemented it, the intention is that each piece of metadata could be signed using Notary. This means you can reliably get back the most recent version of that piece of metadata and know that it was put in place by someone with the authority to do so. 

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

# Proof of concept 

In this proof of concept:  

* we store arbitrary metadata within the Docker registry 
* we store a "manifest" for the repository with the fixed tag "_manifest"
* the manifest is a json file with references to all the metadata stored for this repository

## How is this better than labels pointing to some arbitrary location where information is stored? 

Putting metadata into the registry itself allows us to leverage both existing technology and existing infrastructure. An organisation that stores images in its own on-premise registry can simply store metadata in it, and if they are using Notary again they can simply re-use the same deployment. The signing of metadata uses exactly the same process as the signing of images, so any existing audits and controls can be re-used. 

## Manifesto data

The manifesto associated with a repository is built using a Dockerfile like this: 

```
FROM scratch
ADD <filename> /data
```

Where <filename> contains all the metadata references for this repository. An example might look like this:

```
{
	"tags": [{
		"tag": "lizrice/imagetest:v1.0",
		"manifest": [{
				"type": "seccomp",
				"digest": "sha256:a2fe22a6d44aa86432adad99481c3ad526ba35af2223df126620d20e38c70fac"
			},
			{
				"type": "approvals",
				"digest": "sha256:6ced8eb4e6a61639601e7073963ec04a80f70a11442157e1dd825f042879a6da"
			},
			{
				"type": "contact",
				"digest": "sha256:e896a0012a3450d9cef7e040eea8bed3fe06188957439fea501a65b62c65b4f1"
			}
		]
	}, 
    {
		"tag": "lizrice/imagetest:v1.1",
		"manifest": [{
				"type": "seccomp",
				"digest": "sha256:b2f72296d04ea36435adae99481c3ad526ba35af2223df126620d20e38c9763c"
			},
			{
				"type": "documentation",
				"digest": "sha256:6ced8eb4e6a61639601e7073963ec04a80f70a11442157e1dd825f042879a6da"
			}
		]
    }]
}
```

As noted below, the image is currently referred to by tag in this prototype, but this should be changed to the SHA digest for the image as the tag can change. 

The *type* of each piece of metadata is simply an arbitrary string to identify that type of data. One possibility is to use standardized names (possibly as defined in the OCI image spec or similar) for the type to indicate that the associated data blob contains JSON in a standardized format (such as the vulnerability scanning report format).

# To Do's 

* Add data signing capabilities and verification with Notary. 
* The manifest file should refer to images by SHA rather than by tag (as the tag can move around). Storing metadata against a particular tag should store it against the SHA currently referred to by that tag. 
* Metadata is currently pushed to a new image tagged (for example) `myorg/myimage:_manifest_<metadata type>`. It would be better to push it directly to a blob. 

