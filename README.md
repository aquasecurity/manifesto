# manifesto
Use Manifesto to store and query metadata for Docker images. This metadata can be information that you want to store about an image *post-build* - where labels are not sufficient. 

Examples of the kind of information you might want to store post-build include: 

* contact information for this image
* seccomp profile
* QA or other approvals for this image. 

Although we haven't yet implemented it, the intention is that each piece of metadata could be signed using Notary. This means you can reliably get back the most recent version of that piece of metadata and know that it was put in place by someone with the authority to do so. 

At the moment this is a Proof of Concept - feedback and ideas very welcome. 

## Demo 

[![asciicast](https://asciinema.org/a/4PJUTsNJa6sDvT3DSc0fJhSTW.png)](https://asciinema.org/a/4PJUTsNJa6sDvT3DSc0fJhSTW)

## Installation

* Clone this repo (or go get aquasecurity/manifesto)
* Go to the directory and `go build .`

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
* we store a "manifesto" for the repository with the fixed tag "_manifesto"
* the manifesto is a json file with references to all the metadata stored for this repository

![Manifesto is stored as an image, which references the data blobs for individual pieces of metadata](https://docs.google.com/drawings/d/1IGm4WnhL3J0hp2hdELrevyn3SMbgs0tlKNHjYIQHqtM/pub?w=960&h=720)

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
	"images": [{
		"image_digest": "70d2f067eb94ec8ab0530068a414d8dbe8c203244ae5d5ad4ba6eb1babd1c1c1",
		"manifesto": [{
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
		"image_digest": "51d2f067eb94ec8ab0531987a414d8dbe8c203244ae5d5ad4ba6eb1babd1d54a",
		"manifesto": [{
				"type": "seccomp",
				"digest": "sha256:b2f72296d04ea36435adae99481c3ad526ba35af2223df126620d20e38c9763c"
			},
			{
				"type": "documentation",
				"digest": "sha256:9ce18eb4e6a66639601e7073963ec04aa0f70a11442157e1d9825f042879abb1"
			}
		]
    }]
}
```

The *type* of each piece of metadata is simply an arbitrary string to identify that type of data. One possibility is to use standardized names (possibly as defined in the OCI image spec or similar) for the type to indicate that the associated data blob contains JSON in a standardized format (such as the vulnerability scanning report format).

## Wait - in Docker, it's *tags* that get signed in Notary. Why is metadata associated with image digests?
When you pull a Docker image tagged, say, 1.4 you'll get whatever the latest signed version tagged 1.4 is. The tag can move between different images (i.e. with different digests) as updates are made, for example to update from 1.4.3 to 1.4.4. 

For many types of image metadata (e.g. approval status, vulnerability scan report),a piece of metadata must be associated with a particular build i.e. identified by the digest. 

When metadata is added, the metadata blob gets signed in Notary, as does the manifesto with the references to the metadata blobs. 

# To Do's 

* Metadata is currently pushed to a new image tagged (for example) `myorg/myimage:_manifesto_<metadata type>`. It would be better to push it directly to a blob (as indicated in the diagram above). 
* Add data signing capabilities and verification with Notary. 
* Code currently execs out to the docker client executable - would be better to use the go client and call the API directly. 
