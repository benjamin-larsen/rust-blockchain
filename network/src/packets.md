# Endianness
All integer-types use Little Endian.

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

HMAC signature signs `Sequence || Next Sequence || H(Basic Header) || H(Payload)` with the Session Key.

*48 bytes*

| Offset (Bytes) |   Field Name   | Field Type |
|---------------:|:--------------:|:----------:|
|              0 |    Sequence    |   UInt64   |
|              8 | Next Sequence  |   UInt64   |
|             16 | HMAC Signature |  byte[32]  |

# Message Types
|  ID   | Name  |
|:-----:|-------|
|   0   | Hello |

# Message - Hello
*This is the only message without the Authentication Header Extension.*

This is the first message as part of the Handshake Sequence.

*152 bytes*

| Offset (Bytes) |  Field Name   | Field Type | Description                                                     |
|---------------:|:-------------:|:----------:|-----------------------------------------------------------------|
|              0 |    Version    |   UInt32   | Node Version                                                    |
|              4 | Magic Number  |   UInt64   | Network-specific Identifier                                     |
|             12 |  Public Key   |  byte[32]  | Node's Public Key                                               |
|             44 | Session Token |  byte[32]  | Ephemeral Token                                                 |
|             76 |  Node Flags   |   UInt32   | Node Flags such as Bootstrap, Minimal/Pruned Node etc.          |
|             80 |   Timestamp   |   UInt64   | Timestamp of this Version Packet, used to avoid replay attacks. |
|             88 |   Signature   |  byte[64]  | Signature of Hello Packet, signed with Node Public Key.         |