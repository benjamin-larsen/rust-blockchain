# Endianness
All integer-types use Little Endian.

# Hashes (H)
The Hashing Function for H() is SHA-256.

# Basic Header
Basic Headers has a Message Type (UInt16), Message Flags (UInt16) and a Packet Length (UInt32)

*8 bytes*

| Offset (Bytes) |  Field Name   | Field Type |
|---------------:|:-------------:|:----------:|
|              0 | Message Type  |   UInt16   |
|              2 | Message Flags |   UInt16   |
|              4 | Packet Length |   UInt32   |

# Extension Headers
Extension Headers are always after Basic Header, and is not included in Packet Length.

# Extension Header - Authentication
Authentication Header is used after handshake, and will be used to authenticate packets with HMAC signatures, and Sequence Numbers.

Session Key: `Shared Secret`

Sequence is encoded into Signature, not required to be in Header, if it isn't correct, the Signature will be invalid.

HMAC signature signs `Sequence || H(Basic Header) || H(Payload)` with the Session Key.

*32 bytes*

| Offset (Bytes) |   Field Name   | Field Type |
|---------------:|:--------------:|:----------:|
|              0 | HMAC Signature |  byte[32]  |

# Message Types
| ID | Name                |
|:--:|---------------------|
| 0  | Hello               |
| 1  | Request Known Peers |
| 2  | Known Peers         |

# Message - Hello
*This is the only message without the Authentication Header Extension.*

This is the first message as part of the Handshake Sequence.

Signature is the last 64 bytes, designed for future-proofing compatability.

Signature is of `H(Version || Magic || Public Key || Session Token || Node Flags || Timestamp)`, i.e. the Hello Message excluding Signature.

**At least** *162 bytes* **not more than** *1024 bytes*

| Offset (Bytes) |    Field Name    | Field Type | Description                                                     |
|---------------:|:----------------:|:----------:|-----------------------------------------------------------------|
|              0 |     Version      |   UInt32   | Node Version                                                    |
|              4 |   Magic Number   |   UInt64   | Network-specific Identifier                                     |
|             12 |    Public Key    |  byte[32]  | Node's Public Key                                               |
|             44 |   Exchange Key   |  byte[32]  | X25519 Public Key                                               |
|             76 |    Node Flags    |   UInt32   | Node Flags such as Bootstrap, Minimal/Pruned Node etc.          |
|             80 |       Port       |   UInt16   | Server Port of peer, 0 if disabled.                             |
|             82 | Initial Sequence |   UInt64   | The Sequence for the first Authenticated Message.               |
|             90 |    Timestamp     |   UInt64   | Timestamp of this Version Packet, used to avoid replay attacks. |
|            ... |    Signature     |  byte[64]  | Signature of Hello Packet, signed with Node Public Key.         |

# Message - Request Known Peers
Message to request known peers from peer.

**Must be** *0 bytes*

Cooldown of 1 minute.

Total of Max Connected and Max Remote can't be more than 32.

## Message Flags
Message Flags will contain the Number of Max Connected and Max Remote peers.

| Offset (Bytes) |  Field Name   | Field Type | Description                                           |
|---------------:|:-------------:|:----------:|-------------------------------------------------------|
|              0 | Max Connected |   UInt8    | The Maximum amount of Connected Peers to return       |
|              1 |  Max Remote   |   UInt8    | The Maximum amount of indirect/remote Peers to return |

# Message - Known Peers
Response to `Request Known Peers` message

**Must be** *18 bytes* **times** (*flags.Connected* **plus** *flags.Remote*)

## Message Flags
Message Flags will contain the Number of Connected and Remote peers returned.

| Offset (Bytes) | Field Name | Field Type | Description                         |
|---------------:|:----------:|:----------:|-------------------------------------|
|              0 | Connected  |   UInt8    | The amount of Connected Peers       |
|              1 |   Remote   |   UInt8    | The amount of indirect/remote Peers |

## Payload

| Offset (Bytes) |   Field Name    |      Field Type       | Description              |
|---------------:|:---------------:|:---------------------:|--------------------------|
|              0 | Connected Peers | peer[flags.Connected] | Array of Connected Peers |
|            ... |  Remote Peers   |  peer[flags.Remote]   | Array of Remote Peers    |

### Peer
*18 bytes*

| Offset (Bytes) | Field Name | Field Type | Description           |
|---------------:|:----------:|:----------:|-----------------------|
|              0 | IP Address |  byte[16]  | IPv6 Address          |
|             16 |    Port    |   UInt16   | Peer's Listening Port |