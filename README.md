# tcpdump_golang

## Prerequisite:

 - github.com/google/gopacket

This can be installed by `$ go get github.com/google/gopacket`

## Build:

After installed the required package, run `$ go build` to generate the binary executable file, 
administrator's permission is required to do the live packet capture.

## Usage:

 - -i  Specify the network interface name (e.g., enp0s3). If not specified, mydump would 
    automatically select a default interface

 - -r  Use offline mode (read log from file), cannot work with -i

 - -s  Specify a string filter ("e.g. -s GET to filter the HTTP GET request"), regex is not supported

If additional argument entered, the additional args would treated as BPF filter, error would 
be raised if there's any syntax error in the expression.

Implemented additional feature: resolve ARP packet, identify DNS traffic

## Implementation:
Used pcap.OpenLive() to open the live port
Used handle.SetBPFFilter() to process the BPF expression
Used strings.Contains() to implement the -s option
Used packet.Layer() to solve the specified layer

## Examples:
`$ sudo ./mydump`