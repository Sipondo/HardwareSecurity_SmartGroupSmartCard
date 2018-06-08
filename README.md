# HardwareSecurity_SmartGroupSmartCard
for the course [Hardware Security (IMC001)](http://www.cs.ru.nl/E.Poll/hw/), Radboud University Nijmegen 2017-2018.
## The NotSoGassed project is the work of Team Zes:

#### Bauke Brenninkmeijer - s4366298
#### Wesley van Hoorn - s4018044
#### Ties Robroek - s4388615
#### Mathijs Sonnemans - s4738799
#### Aniek den Teuling - s1010747


## Overview
This is an implementation of a JavaCard petrol rationing system. It is based on
the Calculator template found on the course website.
The template only consists of some very basic JavaCard examples. There is no
real cryptography present. All protocols and systems have thus been implemented
by ourselves.

We have developed the project solely on an HP EliteBook 840 G2 running Windows.
This laptop is an enterprise machine that has a dedicated card reader. We
have simply utilized this card reader instead of the supplied external card readers.
The system has been developed on Java JDK 8 in combination with Javacard 2.2.1.
We have used the corresponding Bouncy Castle release for our terminal-side
cryptography. We have installed our JavaCard applets using the GlobalPlatform
system. Please feel free to utilize the supplied .bat files (compile.bat, mount.bat
  and build.bat) to run the code.

All code has been documented using standard java documentation. The documentation
has been generated using the [atom package Docblockr](https://atom.io/packages/docblockr).
This should be mostly compatible with JavaDoc implementations.
