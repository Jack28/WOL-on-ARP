# WOL-on-ARP

Sniffer to wake machines up on ARP request

## Disclaimer

More a proof of concept and example than an ultimate implementation.
I was asked to release this code, blame my friend.

Fully working though!

## Basic funcionality

Scapy reads on the local interface and reacts on ARP requests for specified IP addresses by sending WOL packages to wake them up.

## Requirements

The sniffer has to be placed in the same network segment (broadcast domain) to be able to see the ARP request.
The client requesting the resource can then also be outside the network since ARP request will be issue by the gateway, router ...

## Scenario

A low power device (can also be connected via wifi) is always powered on and wakes up bigger machines.
