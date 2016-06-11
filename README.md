# PDOD Wireshark Plugin

A wireshark dissector for the protocol of Pokémon Dawn of Darkness.

## The protocol

Binary protocol, with some parts in ASCII. XOR encryption with two fixed keys.

One key for the packets from the client to the server, another for the packets from the server to the client.

The position in the encryption key is saved between two encryptions. Because of this and because I do not know how to reuse a variable from a previous packet using a Wireshark plugin, the dissector will brute-force the 256 possible values.
