---
title: "Preliminary design of a small tracking RADAR for LEO space objects"
authors:
- Giovanni Pecoraro
- Ernestina Cianca
- Gaetano Marino
- Marina Ruggieri
author_notes: []
date: "2016-03-04T00:00:00Z"
doi: "http://dx.doi.org/10.1109/AERO.2017.7943804"

# Schedule page publish date (NOT publication's date).
publishDate: "2016-03-04T00:00:00Z"

# Publication type.
# Legend: 0 = Uncategorized; 1 = Conference paper; 2 = Journal article;
# 3 = Preprint / Working Paper; 4 = Report; 5 = Book; 6 = Book section;
# 7 = Thesis; 8 = Patent
publication_types: ["1"]

# Publication name and optional abbreviated publication name.
publication: "*2017 IEEE Aerospace Conference*"
publication_short: ""

abstract: The near Earth environment has radically changed since the first launch of Sputnik in 1957. So far, the number of uncontrolled artificial objects orbiting around the Earth has incredibly increased and the need of protecting space systems has become almost common to all spacecraft operators. Even though they are currently supported by the large U.S. Space Surveillance Network, most of them have noticed the necessity of creating their own space surveillance sensors. This paper presents a preliminary design of a small and easy to implement radar able to track LEO objects and provide orbits that are more accurate than Two-Line Element (TLE) orbits available online, which do not allow to perform a safe collision avoidance analysis. The adopted configuration is a monostatic pulsed radar with a maximum unambiguous range of 3000 km, a range resolution and angular resolutions of 20 m and 0.01°, respectively. According to the theoretical assessment, the proposed radar is able to detect targets with a Radar Cross Section (RCS) of at least 1 sq. m., which means circular targets with a minimum radius of 50 cm, with a detection probability of 0.9 and a false alarm probability of 0.1. To assess the radar performance, it has been developed CASSIM (Collision Avoidance System SIMulator), which models the system at all stages, from the targets to the signal processing techniques, going through the synthesis of the transmitted and received signals. The simulations have been conducted considering a scenario described in a Collision Data Message (CDM) sent by the U.S. Space Surveillance Network. The simulations have involved the less accurate TLE orbit as radar input and the CDM State Vector orbits as reference to model the simulated target. Results have shown that the radar orbit is comparable to the accurate CDM orbit and that the closest approach distance is very similar to the one indicated in the message (less than 30 m error on all components). The analysis presented in this paper shows the feasibility of this small and simple radar able to get more accurate orbits than TLEs. Moreover, it proved that a collision avoidance analysis based on the radar orbit can be equivalent and could be adequately integrated to the use of the U.S. Space Surveillance Network data.

# Summary. An optional shortened abstract.
summary:

tags:
  - Space
  - RADAR
  - LEO

featured: false

# links:
# - name: ""
#   url: ""
url_pdf: 'https://www.researchgate.net/profile/Giovanni-Pecoraro/publication/317597367_Preliminary_design_of_a_small_tracking_RADAR_for_LEO_space_objects/links/59e7d0d30f7e9bc89b508aff/Preliminary-design-of-a-small-tracking-RADAR-for-LEO-space-objects.pdf'
url_code: ''
url_dataset: ''
url_poster: ''
url_project: ''
url_slides: ''
url_source: ''
url_video: ''

# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder. 
image:
  caption: 'Image credit: [**Giovanni Pecoraro**](https://unsplash.com/photos/jdD8gXaTZsc)'
  focal_point: ""
  preview_only: false

# Associated Projects (optional).
#   Associate this publication with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `internal-project` references `content/project/internal-project/index.md`.
#   Otherwise, set `projects: []`.
projects: []

# Slides (optional).
#   Associate this publication with Markdown slides.
#   Simply enter your slide deck's filename without extension.
#   E.g. `slides: "example"` references `content/slides/example/index.md`.
#   Otherwise, set `slides: ''`.
slides: ''
---

<!-- 
{{% callout note %}}
Click the *Cite* button above to demo the feature to enable visitors to import publication metadata into their reference management software.
{{% /callout %}}

{{% callout note %}}
Create your slides in Markdown - click the *Slides* button to check out the example.
{{% /callout %}}

Supplementary notes can be added here, including [code, math, and images](https://wowchemy.com/docs/writing-markdown-latex/). 
-->
