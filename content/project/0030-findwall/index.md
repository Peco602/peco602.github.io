---
title: FindWall
summary: FindWall is Python script that allows to understand if your network provider is limiting your access to the Internet by blocking any TCP/UDP port.
tags:
  - Cyber Security
  - Python

date: '2022-05-20T00:00:00Z'

# Optional external URL for project (replaces project detail page).
external_link: ''

image:
  caption: Photo by Giovanni Pecoraro
  focal_point: Smart

links:
url_code: 'https://github.com/Peco602/findwall'
url_pdf: ''
url_slides: ''
url_video: ''

# Slides (optional).
#   Associate this project with Markdown slides.
#   Simply enter your slide deck's filename without extension.
#   E.g. `slides = "example-slides"` references `content/slides/example-slides.md`.
#   Otherwise, set `slides = ""`.
slides: ''
---

## What does it do?

FindWall is Python script that allows to understand if your network provider is limiting your access to the Internet by blocking any TCP/UDP port. In order to perform this check FindWall needs to connect a public VPS of your property. FindWall performs the following actions:

1. Connects to the VPS via SSH
2. Opens a port in listening mode
3. Tries to connect to that port from the local machine
4. Closes the port

## How do you use it?

<img src="./demo.gif" width="100%"/>

To use FindWall you just need an account on a public VPS. The account must have root access if you want to test ports in the range `1-1024`. The root account is also required to automatically install the tool `nc` to open ports.

```bashcon
$ pip install -r requirements
$ python findwall.py --help

=====================================================================================

        ███████╗██╗███╗   ██╗██████╗ ██╗    ██╗ █████╗ ██╗     ██╗     
        ██╔════╝██║████╗  ██║██╔══██╗██║    ██║██╔══██╗██║     ██║     
        █████╗  ██║██╔██╗ ██║██║  ██║██║ █╗ ██║███████║██║     ██║     
        ██╔══╝  ██║██║╚██╗██║██║  ██║██║███╗██║██╔══██║██║     ██║     
        ██║     ██║██║ ╚████║██████╔╝╚███╔███╔╝██║  ██║███████╗███████╗
        ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝

=====================================================================================

usage: findwall.py [-h] --ssh-host SSH_HOST [--ssh-port SSH_PORT] --ssh-username SSH_USERNAME [--ssh-password SSH_PASSWORD] [--ask-ssh-pass] [--ssh-key SSH_KEY] --ports PORTS [--udp]
                   [--threads THREADS]

Check if someone is blocking you!

optional arguments:
  -h, --help            show this help message and exit
  --ssh-host SSH_HOST   Remote host
  --ssh-port SSH_PORT   Remote SSH port
  --ssh-username SSH_USERNAME
                        Remote SSH username
  --ssh-password SSH_PASSWORD
                        Remote SSH password
  --ask-ssh-pass        Ask for remote SSH password
  --ssh-key SSH_KEY     Remote SSH private key
  --ports PORTS         Port range to scan (default: 1-1024)
  --udp                 Scan in UDP
  --threads THREADS     Number of threads (default: 1)
```

As an example:

```bashcon
$ python findwall.py --ssh-host 172.17.0.2 --ssh-port 22 --ssh-username test --ssh-password test --ports 8000-8010 --threads 3
```