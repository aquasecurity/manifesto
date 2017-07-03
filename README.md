# manifesto
Use Manifesto to store and query metadata for Docker images. This metadata could be information that you want to store about an image *post-build* - so labels are not sufficient. 

Examples of the kind of information you might want to store post-build include: 

* contact information for this image
* seccomp profile
* QA or other approvals for this image. 

In this proof of concept:  

* we store arbitrary metadata within the Docker registry 
* we store a "manifest" for the repository with the fixed tag "_manifest"
* the manifest is a json file with references to all the metadata stored for this repository

The intention is that each piece of metadata could be signed using Notary.
