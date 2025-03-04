
# Soundscape - a personal music streaming server
[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/xenking/Soundscape%20github%2FSoundscape?type=cf-1)]( https://g.codefresh.io/public/accounts/xenking/pipelines/5d52d1f5ce70269d51b9d2f1)
[![Code Climate]( https://api.codeclimate.com/v1/badges/37e03cff518aaf901247/maintainability)]( https://codeclimate.com/github/xenking/soundscape/maintainability)
[![CircleCI](https://circleci.com/gh/xenking/soundscape.svg?style=svg)](https://circleci.com/gh/xenking/soundscape)

![Screencast](https://raw.githubusercontent.com/soundscapecloud/soundscape/master/screencast1.gif)

![Screenshot - Playlists](https://raw.githubusercontent.com/soundscapecloud/soundscape/master/screenshot1.png?updatedv2)
![Screenshot - Library](https://raw.githubusercontent.com/soundscapecloud/soundscape/master/screenshot2.png?updatedv2)
![Screenshot - Import](https://raw.githubusercontent.com/soundscapecloud/soundscape/master/screenshot3.png?updatedv2)

## Features

* **Import from YouTube**
  * Save any YouTube video as a song in your library
* **Keep your entire music collection in the cloud**
  * Store thousands of songs on your private server
* **Listen to your music anywhere**
  * Stream from any desktop or mobile device
* **Create custom playlists**
  * Add your music to multiple playlists
* **Share your playlists**
  * Let your friends listen to any playlist using the private URL

## Help / Reporting Bugs

Email soundscape@portal.cloud

## Run Soundscape on a VPS

Running Soundscape on a VPS is designed to be as simple as possible.

  * Public Docker image
  * Single static Go binary with assets bundled
  * Automatic TLS using Let's Encrypt
  * Redirects http to https
  * Works with a reverse proxy or standalone

### 1. Get a server

**Recommended Specs**

* Type: VPS or dedicated
* Distribution: Ubuntu 16.04 (Xenial)
* Memory: 512MB
* Storage: 5GB+

**Recommended Providers**

* [OVH](https://www.ovh.com/)
* [Scaleway](https://www.scaleway.com/)

### 2. Add a DNS record

Create a DNS `A` record in your domain pointing to your server's IP address.

**Example:** `music.example.com  A  172.16.1.1`

### 3. Enabling Let's Encrypt (optional)

When enabled with the `--letsencrypt` flag, soundscape runs a TLS ("SSL") https server on port 443. It also runs a standard web server on port 80 to redirect clients to the secure server.

**Requirements**

* Your server must have a publicly resolvable DNS record.
* Your server must be reachable over the internet on ports 80 and 443.

### 4. Run the static binary

Replace `amd64` with `arm64` or `armv7` depending on your architecture.

```bash

# Install ffmpeg.
$ sudo apt-get update
$ sudo apt-get install -y wget ffmpeg

# Download the soundscape binary.
$ sudo wget -O /usr/bin/soundscape https://github.com/soundscapecloud/soundscape/raw/master/soundscape-linux-amd64

# Make it executable.
$ sudo chmod +x /usr/bin/soundscape

# Allow it to bind to privileged ports 80 and 443 as non-root (this is also a potential risk).
$ sudo setcap cap_net_bind_service=+ep /usr/bin/soundscape

# Create your soundscape directory.
$ mkdir $HOME/Music

# (optional) Set a password (or one will be generated and printed in the log)
$ echo "mypassword" >$HOME/Music/.authsecret

# Run with Let's Encrypt enabled for automatic TLS setup (your server must be internet accessible).
$ soundscape --http-host music.example.com --http-username $USER --data-dir $HOME/Music --letsencrypt
1.503869865804371e+09    info    Soundscape URL: https://music.example.com/soundscape/
1.503869865804527e+09    info    Login credentials:  <username>  /  <password>

```

## Run behind an nginx reverse proxy

### Configure nginx

#### 1. Basic auth with htpasswd

```bash
# Create the htpassword file, setting a password.
$ sudo htpasswd -c /etc/nginx/soundscape.htpasswd <username>
New password: 
Re-type new password: 
Adding password for user <username>

# Verify that you've created your htpasswd file correctly.
$ sudo cat /etc/nginx/soundscape.htpasswd
<username>:$apr1$9MuKubBu315eW3IjIy/Ci290dAtIac/

```

#### 2. Reverse proxying with authentication

Run `soundscape` on localhost port 8000 with reverse proxy authentication, using Docker or not.

**Note:** You must specify `--reverse-proxy-ip` to disable basic auth and enable `X-Authenticated-User` header auth.

```bash
$ soundscape --http-addr 127.0.0.1:8000 --http-host music.example.com --reverse-proxy-ip 127.0.0.1

```

You might edit `/etc/nginx/sites-enabled/default` or wherever your nginx config lives.

```
server {
    server_name music.example.com;
    listen 80;

    # Using TLS (recommended)
    # listen 443;
    # ssl_certificate music.example.com.crt;
    # ssl_certificate_key music.example.com.key;

    # Redirect requests for "/" to "/soundscape/" (or use "location / {}" below)
    # rewrite ^/$ /soundscape/ permanent;

    location /soundscape/ {
        auth_basic "Soundscape";
        auth_basic_user_file /etc/nginx/soundscape.htpasswd;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Forwards username to Soundscape backend (required for auth)
        proxy_set_header X-Authenticated-User $remote_user;

        proxy_pass http://localhost:8000;
    }
}

```

## Run the Docker Image

Probably the easiest way to run Soundscape is using the Docker image.

### 1. Install Docker

```bash
# Update apt
$ sudo apt-get update

# Remove old docker install.
$ sudo apt-get remove docker docker-engine docker.io

# Ensure we have basics for apt-get.
$ sudo apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common

# Add Docker's public key.
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

# Add Docker's apt repo
$ sudo add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) \
    stable"

# Update apt
$ sudo apt-get update

# Install Docker
$ sudo apt-get install docker-ce

# Run the hello-world test image
$ sudo docker run hello-world

```

### 2. Run the Docker image

The official image is `soundscapecloud/soundscape`, which should run in any up-to-date Docker environment.

```bash

# Your download directory should be bind-mounted as `/data`
# inside the container using the `--volume` flag (see below).
$ mkdir $HOME/Music

# Set a password (default: a password is generated and printed in the log output)
$ echo "mypassword" >$HOME/Music/.authsecret

# Create the container.
$ sudo docker create \
    --name soundscape \
    --init \
    --restart always \
    --publish 80:80 \
    --publish 443:443 \
    --volume $HOME/Music:/data \
    soundscapecloud/soundscape:latest --http-host music.example.com --http-username $USER --letsencrypt

# Run the container
$ sudo docker start soundscape

# View logs for the container
$ sudo docker logs -f soundscape
1.503869865804371e+09    info    Soundscape URL: https://music.example.com/soundscape/
1.503869865804527e+09    info    Login credentials:  <username> /  <password>

```

### 3. Updating the container image

Pull the latest image, remove the container, and re-create the container as explained above.

```bash
# Pull the latest image
$ sudo docker pull soundscapecloud/soundscape

# Stop the container
$ sudo docker stop soundscape

# Remove the container (data is stored on the mounted volume)
$ sudo docker rm soundscape

# Re-create and start the container
$ sudo docker create ... (see above)

```

## Usage

```bash
$ soundscape --help
Usage of soundscape:
  -backlink string
        backlink (optional)
  -data-dir string
        data directory (default "/data")
  -debug
        debug mode
  -http-addr string
        listen address (default ":80")
  -http-host string
        HTTP host
  -http-prefix string
        HTTP URL prefix (not actually supported yet!) (default "/soundscape")
  -http-username string
        HTTP basic auth username (default "soundscape")
  -letsencrypt
        enable TLS using Let's Encrypt
  -reverse-proxy-header string
        reverse proxy auth header (default "X-Authenticated-User")
  -reverse-proxy-ip string
        reverse proxy auth IP

```

## Building

The easiest way to build the static binary is using the `Dockerfile.build` file.

```bash
# Clone the git repo
$ git clone https://github.com/soundscapecloud/soundscape.git

$ cd soundscape/

# Compile the code and create a Docker image for it.
$ sudo docker build --build-arg BUILD_VERSION=$(git rev-parse --short HEAD) -t soundscape:build -f Dockerfile.build .

# Create a container based on the image we just built.
$ sudo docker create --name soundscapebuild soundscape:build

# Extract the binary from the image.
$ sudo docker cp soundscapebuild:/usr/bin/soundscape-linux-amd64 soundscape-linux-amd64

# armv7
# $ sudo docker cp soundscapebuild:/usr/bin/soundscape-linux-amd64 soundscape-linux-armv7

# arm64
# $ sudo docker cp soundscapebuild:/usr/bin/soundscape-linux-amd64 soundscape-linux-arm64

# We're done with the build container.
$ sudo docker rm soundscapebuild

# Inspect the binary.
$ file soundscape-linux-amd64
soundscape-linux-amd64: ELF 64-bit LSB  executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=c5a6f3a2e15c8ca511bec52c357ebf8f4g542233, stripped

# Run the binary.
$ ./soundscape-linux-amd64 --help

# Build a tiny alpine "runner" image.
# $ sudo docker build -t soundscape:latest .
```
