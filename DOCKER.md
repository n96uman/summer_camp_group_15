## what is docker?
    - docker is a platform for building, running and shipping applications in consistence matters.
    - different version run at ones.
 
## virtual machines VS containers 
    - a virtual machine is abstract of a machine.
    - need full=blown os , slow to start and resource intensive.
    - containers: more light weight , fast and  only one OS.
 
## Architecture of docker
    - client->docker Engine using REST API.
 ## installing Docker
     https://docs.docker.com/get-docker/
     https://hub.docker.com
##   Development Work flow
 1. take application make a simple change to docker it.
     - create a docker file: that have instruction use to package of application to image.
     - we tell docker to start a container using that image.
     - after that we can push it to docker-hub(like github for dockers).
## docker in action
 - for simple js code: start with OS -> install Node -> copy app files -> Run node app.
 - inside a docker file: 
    - FROM node:alpine
    - COPY . /app
    - WORKDIR /app
    - CMD node /app/app.js
- to create an image in command line: docker build -t "docker name" .
- to see the images: docker image ls.
- to run a docker image: docker run "image name".
- to start container in interact mood: docker run -it "docker image".
- 