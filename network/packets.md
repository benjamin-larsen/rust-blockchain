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

Ec = Client Ephemeral Token
Es = Server Ephemeral Token
Session Key: `H(Ec || Es || Shared Secret)`

Sequence is encoded into Signature, not required to be in Header, if it isn't correct, the Signature will be invalid.

HMAC signature signs `Sequence || H(Basic Header) || H(Payload)` with the Session Key.

*32 bytes*

| Offset (Bytes) |   Field Name   | Field Type |
|---------------:|:--------------:|:----------:|
|              0 | HMAC Signature |  byte[32]  |

# Message Types
|  ID   | Name  |
|:-----:|-------|
|   0   | Hello |

# Message - Hello
*This is the only message without the Authentication Header Extension.*

This is the first message as part of the Handshake Sequence.

Signature is of `H(Version || Magic || Public Key || Session Token || Node Flags || Timestamp)`, i.e. the Hello Message excluding Signature.

*160 bytes*

| Offset (Bytes) |    Field Name    | Field Type | Description                                                     |
|---------------:|:----------------:|:----------:|-----------------------------------------------------------------|
|              0 |     Version      |   UInt32   | Node Version                                                    |
|              4 |   Magic Number   |   UInt64   | Network-specific Identifier                                     |
|             12 |    Public Key    |  byte[32]  | Node's Public Key                                               |
|             44 |  Session Token   |  byte[32]  | Ephemeral Token                                                 |
|             76 |    Node Flags    |   UInt32   | Node Flags such as Bootstrap, Minimal/Pruned Node etc.          |
|             80 | Initial Sequence |   UInt64   | The Sequence for the first Authenticated Message.               |
|             88 |    Timestamp     |   UInt64   | Timestamp of this Version Packet, used to avoid replay attacks. |
|             96 |    Signature     |  byte[64]  | Signature of Hello Packet, signed with Node Public Key.         |