---
title: RustHunter
summary: RustHunter is a modular incident response framework to build and compare environmental baselines. It is written in Rust and uses Ansible to collect data across multiple hosts.
tags:
  - Cyber Security
  - Blue Teaming
  - Incident Response
  - Rust

date: '2022-05-15T00:00:00Z'

# Optional external URL for project (replaces project detail page).
external_link: ''

image:
  caption: Photo by Giovanni Pecoraro
  focal_point: Smart

links:
  - icon: book
    icon_pack: fas
    name: Documentation
    url: https://rusthunter.readthedocs.io/
url_code: 'https://github.com/Peco602/rusthunter'
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

RustHunter is a modular incident response framework to build and compare environmental baselines. It is written in Rust and uses Ansible to collect data across multiple hosts.

Due to the following features it can be also employed to perform threat hunting and incident handling:

- **Multi-Platform**: it is able to collect data from both Windows, Linux and macOS machines;
- **Agentless**: the usage of the Ansible technology based on SSH and WinRM allows to overcome the requirement of a local agent waiting for a task to be accomplished;
- **Easily Deployable**: it is cross-platform and can be deployed both on premises and in a Cloud-based environment. A Bash and a PowerShell scripts have been developed to execute the tool respectively from a Linux and Windows machine;
- **Easily Expandable**: it provides developer-ready Rust specifications offering an easy way to expand the product features by writing custom modules to collect additional machine data.