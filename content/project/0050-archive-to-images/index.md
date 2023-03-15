---
title: Archive-To-Images
summary: Archive-To-Images is a Python CLI to transform archives into images and reverse.
tags:
  - Python

date: '2023-03-15T00:00:00Z'

# Optional external URL for project (replaces project detail page).
external_link: ''

image:
  caption: Photo by Giovanni Pecoraro
  focal_point: Smart

links:
url_code: 'https://github.com/Peco602/archive-to-images'
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

## Introduction

Since some cloud providers offer free unlimited picture-only storage, the **Archive-To-Images** library allows to convert any collection of files into pictures to be uploaded without any additional cost. 


## Installation

The package can be easily installed via `pip` package manager:

```bash
$ pip install archive-to-images
```

## Usage as CLI

### Transform to images

```bash
$ archive-to-images transform --help

 Usage: archive-to-images transform [OPTIONS]                                                                           
                                                                                                                        
 Transforms an archive into multiple images.                                                                            
                                                                                                                        
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --path     -p      TEXT            Path containing data to be archived. [default: None] [required]                │
│ *  --name     -n      TEXT            Name of the archive. [default: None] [required]                                │
│    --size     -s      [0.5|1|2|5|10]  Maximum size of an image in MB. [default: 1]                                   │
│    --encrypt  -e                      Protect archive with password.                                                 │
│    --verbose  -v                      Enable verbose output.                                                         │
│    --help                             Show this message and exit.                                                    │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Create an image collection from data contained in multiple paths.

```bash
$ archive-to-images transform --path /home/alice/Desktop --path /home/alice/Documents --name ARCHIVE_ALICE
```

Set the maximum image size in MB (default: 1):

```bash
$ archive-to-images transform --path /home/alice/Desktop --path /home/alice/Documents --name ARCHIVE_ALICE -s 5
```

Encrypt data with a password:

```bash
$ archive-to-images transform --path /home/alice/Desktop --path /home/alice/Documents --name ARCHIVE_ALICE -s 5 -e
```

### Restore from images

```bash
$ archive-to-images restore --help

 Usage: archive-to-images restore [OPTIONS]                                                                             
                                                                                                                        
 Restores an archive from multiple images.                                                                              
                                                                                                                        
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --path     -p      TEXT  Path containing images to be processed. [default: None] [required]                       │
│    --verbose  -v            Enable verbose output.                                                                   │
│    --help                   Show this message and exit.                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Restore the archives stored in image collections:

```bash
$ archive-to-images restore --path /home/alice/Downloads/Album1 --path /home/alice/Downloads/Album2
```

The library will automatically find all the archives stored in the images and will output a `zip` archive for each one.


## Usage as docker

Run the docker image and bind the current folder to the `workspace` path inside the container:

```bash
$ docker run -it --rm -v $(pwd):/workspace peco602/archive_to_images:latest bash
```

then it is possible to use the CLI directly from the container bash.
