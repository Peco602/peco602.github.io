---
title: "DICOM images in Python: An overview"
subtitle: A key step towards the application of Deep Learning to medical images is the understanding of Digital Imaging and Communications in Medicine (DICOM) which represents the standard for the communication and management of medical imaging.

# Summary for listings and search engines
summary: A key step towards the application of Deep Learning to medical images is the understanding of Digital Imaging and Communications in Medicine (DICOM) which represents the standard for the communication and management of medical imaging.

# Link this post with a project
projects: []

# Date published
date: '2022-09-29T00:00:00Z'

# Date updated
lastmod: '2022-09-29T00:00:00Z'

# Is this an unpublished draft?
draft: false

# Show this page in the Featured widget?
featured: true

# Featured image
# Place an image named `featured.jpg/png` in this page's folder and customize its options here.
image:
  caption: 'Image credit: [**Giovanni Pecoraro**](https://unsplash.com/photos/CpkOjOcXdUY)'
  focal_point: ''
  placement: 2
  preview_only: false

authors:
  - admin

tags:
  - Image Processing
  - Deep Learning
  - Medical
  - DICOM
  - Python
  
categories:
  - Deep Learning
  - Python

---

## Introduction

DICOM or Digital Imaging and Communications in medicine are image files sourced from different modalities, e.g., CT or MRI scans, and are based on an [international standard](https://www.dicomstandard.org/) to transmit, store, retrieve, print, process, and display medical imaging information. DICOM files not only contain the image, but also include additional data, such as patient identifier, date of birth, age, sex, and other useful information about the diagnosis. The following table provides an overview about the main components of a medical image based on the DICOM standard.

| Component | Description |
| --- | --- |
| Metadata | Information about the patient and the image |
| Pixel Depth | Number of bits used to encode the information of each pixel. For example, an 8-bit raster can have 256 unique values that range from 0 to 255. |
| Photometric Interpretation | It specifies how the pixel data should be interpreted for the correct image display as a monochrome or color image. To specify if the color information is or is not stored in the image pixel values, we introduce the concept of samples per pixel, also known as (number of channels). |
| Pixel Data | Section where the numerical values of the medical image pixels are stored.  |

The DICOM standard allows DICOM file creators to use private data elements to store information that is not defined by the DICOM standard itself.



## Reading DICOM files

https://pydicom.github.io/pydicom/stable/old/base_element.html

Multiple free DICOM viewers are available online (a list is available [here](https://technologyadvice.com/blog/healthcare/5-dicom-viewers/)). Anyway, in case some additional automated analysis/processing is needed, DICOM images can be also opened in Python, but the some additional libraries are needed: 

- **[Pydicom](https://pypi.org/project/pydicom/)**: DICOM files reading and decoding library
- **[Numpy](https://numpy.org/install/)**: Array manipulation library
- **[Pillow](https://pypi.org/project/Pillow/2.2.2/)**: Image processing library
- **[Matplotlib](https://matplotlib.org/stable/users/installing/index.html)**: Image visualization library

and can be installed via the following command:

```bash
pip install pydicom numpy pillow matplotlib
```

A DICOM dataset at a given path can be read via [`dcmread()`](https://pydicom.github.io/pydicom/stable/reference/generated/pydicom.filereader.dcmread.html#pydicom.filereader.dcmread), which returns a [`FileDataset`](https://pydicom.github.io/pydicom/stable/reference/generated/pydicom.dataset.FileDataset.html#pydicom.dataset.FileDataset) instance:

```python
>>> from pydicom import dcmread
>>> PATH = '/home/user/Desktop/exam/MD44PKO2/PB4KONGE/I4000000'
>>> ds = dcmread(PATH)
>>> type(ds)
<class 'pydicom.dataset.FileDataset'>
```

Then, it is possible to view the contents of the entire dataset by using [`print()`](https://docs.python.org/3/library/functions.html#print):

<details>
  <summary>Click me</summary>

  ```python
  >>> print(ds)
  Dataset.file_meta -------------------------------
  (0002, 0000) File Meta Information Group Length  UL: 168
  (0002, 0001) File Meta Information Version       OB: b'\x00\x01'
  (0002, 0002) Media Storage SOP Class UID         UI: CT Image Storage
  (0002, 0003) Media Storage SOP Instance UID      UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002206
  (0002, 0010) Transfer Syntax UID                 UI: Explicit VR Little Endian
  (0002, 0012) Implementation Class UID            UI: 1.2.840.113704.7.0.2
  -------------------------------------------------
  (0008, 0008) Image Type                          CS: ['ORIGINAL', 'PRIMARY', 'AXIAL', 'CT_SOM5 SEQ']
  (0008, 0016) SOP Class UID                       UI: CT Image Storage
  (0008, 0018) SOP Instance UID                    UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002206
  (0008, 0020) Study Date                          DA: '20221215'
  (0008, 0021) Series Date                         DA: '20221215'
  (0008, 0022) Acquisition Date                    DA: '20221215'
  (0008, 0023) Content Date                        DA: '20221215'
  (0008, 0030) Study Time                          TM: '162614'
  (0008, 0031) Series Time                         TM: '162758'
  (0008, 0032) Acquisition Time                    TM: '162821.901196'
  (0008, 0033) Content Time                        TM: '162821.901196'
  (0008, 0050) Accession Number                    SH: '5895682501'
  (0008, 0060) Modality                            CS: 'CT'
  (0008, 0061) Modalities in Study                 CS: ['CT', 'SR']
  (0008, 0070) Manufacturer                        LO: 'SIEMENS'
  (0008, 0080) Institution Name                    LO: 'Campus Biomedico'
  (0008, 0081) Institution Address                 ST: 'Via Torsiello\r\nRom.0110E4.\r\nRom\r\nIT'
  (0008, 0090) Referring Physician's Name          PN: 'MEDICO^REFERTANTE'
  (0008, 1010) Station Name                        SH: 'CT55050'
  (0008, 1030) Study Description                   LO: 'TC CRANIO (CAPO)'
  (0008, 1032)  Procedure Code Sequence  1 item(s) ----
    (0008, 0100) Code Value                          SH: 'RS0932'
    (0008, 0104) Code Meaning                        LO: 'TC CRANIO (CAPO)'
    ---------
  (0008, 103e) Series Description                  LO: 'HeadSeq  2.4  H23s'
  (0008, 1048) Physician(s) of Record              PN: '10440^NEUROLOGIA'
  (0008, 1050) Performing Physician's Name         PN: 'NonDisp'
  (0008, 1080) Admitting Diagnoses Description     LO: '-'
  (0008, 1090) Manufacturer's Model Name           LO: 'Sensation 64'
  (0008, 1140)  Referenced Image Sequence  1 item(s) ----
    (0008, 1150) Referenced SOP Class UID            UI: CT Image Storage
    (0008, 1155) Referenced SOP Instance UID         UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002194
    ---------
  (0008, 2112)  Source Image Sequence  1 item(s) ----
    (0008, 1150) Referenced SOP Class UID            UI: 1.3.12.2.1107.5.9.1
    (0008, 1155) Referenced SOP Instance UID         UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002201
    ---------
  (0009, 0010) Private Creator                     LO: 'SIEMENS CT VA1 DUMMY'
  (0010, 0010) Patient's Name                      PN: 'DI MARTINO^ONOFRIO'
  (0010, 0020) Patient ID                          LO: '81145704'
  (0010, 0021) Issuer of Patient ID                LO: 'X1V1_MPI'
  (0010, 0030) Patient's Birth Date                DA: '19460507'
  (0010, 0040) Patient's Sex                       CS: 'M'
  (0010, 1010) Patient's Age                       AS: '076Y'
  (0010, 1040) Patient's Address                   CS: '__POMEZIA_RM_00071'
  (0018, 0015) Body Part Examined                  CS: 'HEAD'
  (0018, 0050) Slice Thickness                     DS: '2.4'
  (0018, 0060) KVP                                 DS: '120.0'
  (0018, 0090) Data Collection Diameter            DS: '500.0'
  (0018, 1000) Device Serial Number                LO: '55050'
  (0018, 1020) Software Versions                   LO: 'syngo CT 2014A'
  (0018, 1030) Protocol Name                       LO: 'CBM_encefalo_SEQ'
  (0018, 1100) Reconstruction Diameter             DS: '232.0'
  (0018, 1110) Distance Source to Detector         DS: '1040.0'
  (0018, 1111) Distance Source to Patient          DS: '570.0'
  (0018, 1120) Gantry/Detector Tilt                DS: '0.0'
  (0018, 1130) Table Height                        DS: '255.0'
  (0018, 1140) Rotation Direction                  CS: 'CW'
  (0018, 1150) Exposure Time                       IS: '1000'
  (0018, 1151) X-Ray Tube Current                  IS: '380'
  (0018, 1152) Exposure                            IS: '380'
  (0018, 1160) Filter Type                         SH: '0'
  (0018, 1170) Generator Power                     IS: '45'
  (0018, 1190) Focal Spot(s)                       DS: '1.2'
  (0018, 1200) Date of Last Calibration            DA: '20221215'
  (0018, 1201) Time of Last Calibration            TM: '073319.000000'
  (0018, 1210) Convolution Kernel                  SH: 'H23s'
  (0018, 5100) Patient Position                    CS: 'HFS'
  (0018, 9306) Single Collimation Width            FD: 0.6
  (0018, 9307) Total Collimation Width             FD: 7.199999999999999
  (0018, 9309) Table Speed                         FD: 0.0
  (0018, 9323) Exposure Modulation Type            CS: 'NONE'
  (0018, 9324) Estimated Dose Saving               FD: 0.0
  (0018, 9345) CTDIvol                             FD: 69.49440000000001
  (0019, 0010) Private Creator                     LO: 'SIEMENS CT VA0  COAD'
  (0020, 000d) Study Instance UID                  UI: 1.2.840.113564.9.1.2015111110072131.20221209153953.25895682501
  (0020, 000e) Series Instance UID                 UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002202
  (0020, 0010) Study ID                            SH: 'CT20221215162611'
  (0020, 0011) Series Number                       IS: '2'
  (0020, 0012) Acquisition Number                  IS: '3'
  (0020, 0013) Instance Number                     IS: '4'
  (0020, 0032) Image Position (Patient)            DS: [-115.7734375, -357.7734375, -189.4]
  (0020, 0037) Image Orientation (Patient)         DS: [1, 0, 0, 0, 1, 0]
  (0020, 0052) Frame of Reference UID              UI: 1.3.12.2.1107.5.1.4.55050.30000022121506293760900002193
  (0020, 1040) Position Reference Indicator        LO: ''
  (0020, 1041) Slice Location                      DS: '-189.4'
  (0020, 1208) Number of Study Related Instances   IS: '546'
  (0020, 4000) Image Comments                      LT: ''
  (0021, 0010) Private Creator                     LO: 'SIEMENS MED'
  (0028, 0002) Samples per Pixel                   US: 1
  (0028, 0004) Photometric Interpretation          CS: 'MONOCHROME2'
  (0028, 0010) Rows                                US: 512
  (0028, 0011) Columns                             US: 512
  (0028, 0030) Pixel Spacing                       DS: [0.453125, 0.453125]
  (0028, 0100) Bits Allocated                      US: 16
  (0028, 0101) Bits Stored                         US: 12
  (0028, 0102) High Bit                            US: 11
  (0028, 0103) Pixel Representation                US: 0
  (0028, 0106) Smallest Image Pixel Value          US: 0
  (0028, 0107) Largest Image Pixel Value           US: 2856
  (0028, 1050) Window Center                       DS: [35, 700]
  (0028, 1051) Window Width                        DS: [80, 3200]
  (0028, 1052) Rescale Intercept                   DS: '-1024.0'
  (0028, 1053) Rescale Slope                       DS: '1.0'
  (0028, 1055) Window Center & Width Explanation   LO: ['WINDOW1', 'WINDOW2']
  (0029, 0010) Private Creator                     LO: 'SIEMENS CSA HEADER'
  (0029, 0011) Private Creator                     LO: 'SIEMENS MEDCOM HEADER'
  (0032, 1032) Requesting Physician                PN: '10440^NEUROLOGIA'
  (0032, 1060) Requested Procedure Description     LO: 'TC CRANIO (CAPO)'
  (0032, 1064)  Requested Procedure Code Sequence  1 item(s) ----
    (0008, 0100) Code Value                          SH: 'RS0932'
    (0008, 0104) Code Meaning                        LO: 'TC CRANIO (CAPO)'
    ---------
  (0040, 0275)  Request Attributes Sequence  1 item(s) ----
    (0040, 0007) Scheduled Procedure Step Descriptio LO: 'TC CRANIO (CAPO)'
    (0040, 0008)  Scheduled Protocol Code Sequence  1 item(s) ----
        (0008, 0100) Code Value                          SH: 'RS0932'
        (0008, 0102) Coding Scheme Designator            SH: 'DSS_MESA'
        (0008, 0104) Code Meaning                        LO: 'TC CRANIO (CAPO)'
        ---------
    (0040, 0009) Scheduled Procedure Step ID         SH: '5895682501'
    ---------
  (0040, 1008) Confidentiality Code                LO: 'N'
  (0088, 0200)  Icon Image Sequence  1 item(s) ----
    (0028, 0002) Samples per Pixel                   US: 1
    (0028, 0004) Photometric Interpretation          CS: 'MONOCHROME2'
    (0028, 0010) Rows                                US: 64
    (0028, 0011) Columns                             US: 64
    (0028, 0034) Pixel Aspect Ratio                  IS: [1, 1]
    (0028, 0100) Bits Allocated                      US: 8
    (0028, 0101) Bits Stored                         US: 8
    (0028, 0102) High Bit                            US: 7
    (0028, 0103) Pixel Representation                US: 0
    (7fe0, 0010) Pixel Data                          OB: Array of 4096 elements
    ---------
  (07a1, 0010) Private Creator                     LO: 'ELSCINT1'
  (07a1, 1002) [number of images in series]        UL: 66
  (07a1, 102a) [Tamar Study Status]                CS: 'APPROVED'
  (07a1, 1040) [Tamar Study Body Part]             CS: 'ABDOMEN'
  (07a1, 1042) Private tag data                    SH: 'R.TARRICONE@CB'
  (07a1, 1043) [Unknown]                           IS: '3'
  (07a1, 1050) [Tamar Site Id]                     US: 31
  (07a1, 1058) Private tag data                    CS: 'A'
  (07a1, 105d) Private tag data                    DT: '20221215163041.000000'
  (07a1, 105f) Private tag data                    CS: 'N'
  (07a1, 1070) Private tag data                    SH: 'RAD^238'
  (07a1, 1071) Private tag data                    SH: 'neuro'
  (07a1, 1085) [Tamar Translate Flags]             UL: 3
  (07a1, 10a7) Private tag data                    LO: '-1'
  (07a1, 10b9) Private tag data                    CS: 'Y'
  (07a1, 10bb) Private tag data                    LO: 'r.Tarricone@cb'
  (07a1, 10bc) Private tag data                    DT: '20221215190728.000000'
  (07a1, 10bd) Private tag data                    LO: 'r.Tarricone@cb'
  (07a1, 10be) Private tag data                    DT: '20221215190728.000000'
  (07a1, 10d0) Private tag data                    LO: '29560006180868'
  (07a3, 0010) Private Creator                     LO: 'ELSCINT1'
  (07a3, 1001) [Tamar Exe Software Version]        LO: '12.2.1.2'
  (07a3, 1003) [Tamar Study Has Sticky Note]       CS: 'N'
  (07a3, 1014) Private tag data                    ST: 'RS0932'
  (07a3, 1017) Private tag data                    SH: 'CM'
  (07a3, 1018) Private tag data                    ST: 'Si richiede TC encefalo di controllo in paziente con ictu'
  (07a3, 101b) Private tag data                    ST: '33103'
  (07a3, 101f) Private tag data                    ST: '7144^CAPPARONI^MASSIMILIANO^CPPMSM80A22H501C^m.capparoni^^^^^^^^^^^^^^^'
  (07a3, 1022) Private tag data                    ST: 'Altro'
  (07a3, 1023) Private tag data                    ST: 'O08'
  (07a3, 1024) Private tag data                    ST: '@cb'
  (07a3, 1055) [Unknown]                           SH: 'N'
  (07a3, 105c) Private tag data                    ST: '0'
  (07a3, 108c) Private tag data                    CS: 'N'
  (07a3, 108f) Private tag data                    CS: 'N'
  (07a3, 109c) [Unknown]                           CS: 'N'
  (07a3, 10b9) Private tag data                    CS: 'N'
  (07a3, 10bb) Private tag data                    CS: 'N'
  (07a3, 10c0)  Private tag data  1 item(s) ----
    (07a3, 0010) Private Creator                     LO: 'ELSCINT1'
    (07a3, 1039) Private tag data                    UL: 61
    (07a3, 10c1) Private tag data                    LO: 'cbmpacs01'
    (07a3, 10c2) Private tag data                    CS: 'FAST_NET'
    (07a3, 10c3) Private tag data                    CS: 'SECURED_CON'
    (07a3, 10c4) Private tag data                    LO: '172.17.8.117'
    (07a3, 10c5) Private tag data                    LO: '22104'
    (07a3, 10c8) Private tag data                    AE: 'cbmpacs01FIR'
    (07a3, 10c9) Private tag data                    CS: 'N'
    (07a3, 10cc) Private tag data                    LO: '1.0.0.0'
    ---------
  (07a3, 10ca)  Private tag data  1 item(s) ----
    (07a3, 0010) Private Creator                     LO: 'ELSCINT1'
    (07a3, 1039) Private tag data                    UL: 61
    (07a3, 10c1) Private tag data                    LO: 'cbmpacs01'
    (07a3, 10c2) Private tag data                    CS: 'FAST_NET'
    (07a3, 10c3) Private tag data                    CS: 'SECURED_CON'
    (07a3, 10c4) Private tag data                    LO: '172.17.8.117'
    (07a3, 10c5) Private tag data                    LO: '22104'
    (07a3, 10c8) Private tag data                    AE: 'cbmpacs01FIR'
    (07a3, 10c9) Private tag data                    CS: 'N'
    (07a3, 10cc) Private tag data                    LO: '1.0.0.0'
    ---------
  (07a3, 10cb)  Private tag data  1 item(s) ----
    (07a3, 0010) Private Creator                     LO: 'ELSCINT1'
    (07a3, 1039) Private tag data                    UL: 61
    (07a3, 10c1) Private tag data                    LO: 'cbmpacs01'
    (07a3, 10c2) Private tag data                    CS: 'FAST_NET'
    (07a3, 10c3) Private tag data                    CS: 'SECURED_CON'
    (07a3, 10c4) Private tag data                    LO: '172.17.8.117'
    (07a3, 10c5) Private tag data                    LO: '22104'
    (07a3, 10c8) Private tag data                    AE: 'cbmpacs01FIR'
    (07a3, 10c9) Private tag data                    CS: 'N'
    (07a3, 10cc) Private tag data                    LO: '1.0.0.0'
    ---------
  (07a3, 10f2) Private tag data                    CS: 'CS PACS REPORT'
  (07a5, 0010) Private Creator                     LO: 'ELSCINT1'
  (07a5, 1010) Private tag data                    UL: 100
  (07a5, 101c) Private tag data                    LO: '0'
  (07a5, 1040) Private tag data                    LO: 'r.Tarricone@cb'
  (07a5, 1041) Private tag data                    DT: '20221215190728.000000'
  (07a5, 1054) Private tag data                    DT: '20221215190728.000000'
  (07a5, 1056) Private tag data                    CS: 'N'
  (07a5, 1059) Private tag data                    IS: '1'
  (07a5, 1069) Private tag data                    AE: 'AN_CT55050'
  (07a5, 1072) Private tag data                    DT: '20221215163041.000000'
  (07a5, 10c8) Private tag data                    CS: 'Y'
  (07a5, 10dc) Private tag data                    UL: 360
  (07a5, 10dd) Private tag data                    FL: 3.0
  (07a5, 10de) Private tag data                    LO: ['tc_cranio', 'neuro']
  (07a5, 10e7) Private tag data                    LO: 'manual_assignment'
  (07a5, 10e8) Private tag data                    IS: '0'
  (7fe0, 0010) Pixel Data                          OW: Array of 524288 elements
  ```

</details>

> **_NOTE:_**  You can also view DICOM files in a collapsible tree using the example program [dcm_qt_tree.py](https://github.com/pydicom/contrib-pydicom/blob/master/plotting-visualization/dcm_qt_tree.py).

## DICOM File-sets and DICOMDIR

A File-set is a collection of DICOM files that share a common naming space. Most people have probably interacted with a File-set without being aware of it; one place they’re frequently used is on the CDs/DVDs containing DICOM data that are given to a patient after a medical procedure (such as an MR or ultrasound). The specification for File-sets is given in [Part 10 of the DICOM Standard](http://dicom.nema.org/medical/dicom/current/output/chtml/part10/chapter_8.html).

Every File-set must contain a single file with the filename **`DICOMDIR`**, the location of which is dependent on the type of media used to store the File-set. For the most commonly used media (DVD, CD, USB, PC file system, etc), the DICOMDIR file will be in the root directory of the File-set. For other media types, [Part 12 of the DICOM Standard](http://dicom.nema.org/medical/dicom/current/output/chtml/part12/ps3.12.html) specifies where the DICOMDIR must be located.

## Viewing DICOM images

https://pydicom.github.io/pydicom/stable/old/working_with_pixel_data.html
https://pydicom.github.io/pydicom/stable/old/viewing_images.html

## How to pre-process DICOM images?

```python
# https://pydicom.github.io/pydicom/stable/tutorials/filesets.html

from pydicom.fileset import FileSet

fs = FileSet('/home/user/Desktop/exam/DICOMDIR')

fi = fs._instances[0]

ds = fi.load()

ds

ds.remove_private_tags()

from pprint import pprint

pprint(ds.dir())

new_image = ds.pixel_array.astype(float)

# Now to use the image we should rescale its pixels and put their values between 0 and 255. So here is the line of code that you need to do that.
import numpy as np
from PIL import Image
scaled_image = (np.maximum(new_image, 0) / new_image.max()) * 255.0

# Now the final part which using the image for our needs. The image that we had in the last part was an array so we will use this array to create the image using the Pillow library. But before that, we need to convert it into 8 bits unsigned integer. Here are the commands that you need to create the image from an array:
scaled_image = np.uint8(scaled_image)
final_image = Image.fromarray(scaled_image)
final_image.show()

ds.SeriesNumber
ds.InstanceNumber

final_image.save('image.jpg')
final_image.save('image.png')

######
from pydicom.pixel_data_handlers import apply_windowing
new_image = apply_windowing(ds.pixel_array, ds, 1)
final_image = Image.fromarray(new_image)
final_image.show()
######

from pydicom.pixel_data_handlers.util import apply_voi, apply_modality_lut
new_image = apply_modality_lut(ds.pixel_array, ds)
final_image = Image.fromarray(new_image)
final_image.show()
```

## How to convert DICOM images to JPEG?

## Conclusions

## References

- [Digital Image and Communications in Medicine](https://www.dicomstandard.org/)
- [Extract DICOM Images Only for Deep Learning | by Nawaf Alageel | Analytics Vidhya | Medium](https://medium.com/analytics-vidhya/dicom-and-deep-learning-63373e99d79a)
- [DICOM File-sets and DICOMDIR — pydicom 2.3.1 documentation](https://pydicom.github.io/pydicom/stable/tutorials/filesets.html)
- [How to read DICOM files into Python | MICHELE SCIPIONI (mscipio.github.io)](https://mscipio.github.io/post/read_dicom_files_in_python/)
- [How To Convert a DICOM Image Into JPG or PNG - PYCAD](https://pycad.co/how-to-convert-a-dicom-image-into-jpg-or-png/)
- [Medical Image Pre-Processing with Python | by Esma Sert | Towards Data Science](https://towardsdatascience.com/medical-image-pre-processing-with-python-d07694852606)
- [DICOM in Python: Importing medical image data into NumPy with PyDICOM and VTK](https://pyscience.wordpress.com/2014/09/08/dicom-in-python-importing-medical-image-data-into-numpy-with-pydicom-and-vtk/)