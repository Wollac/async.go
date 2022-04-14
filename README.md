# async.go

This repository contains Go implementations of selected primitives in asynchronous distributed computing.

## Packages
It contains the following general packages:
- `rbc` implements Bracha's Reliable Broadcast (https://core.ac.uk/download/pdf/82523202.pdf).
- `acss` implements a slightly modified version of hbACSS0 (https://ia.cr/2021/159) using Feldman's VSS scheme instead of polynomial commitments.
