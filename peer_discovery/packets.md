# Transport Layer
The Peer Discovery network will be over UDP, with a lightweight Reliability Layer.

# Payload Limit
No payload shall exceed 1024 bytes.

# Duplication Philosophy
To make this protocol as lightweight as possible, with support of tens of thousands of Connections.

This requires a Minimal and Predictable state to be tracked, which leaves out the possibility of tracking Seen Messages.

Only Connection and Reset will be tracked with Attempts flag.

# Header
**4 bytes**

| Offset (Bytes) |  Field Name   | Field Type | Description                                      |
|---------------:|:-------------:|:----------:|--------------------------------------------------|
|              0 | Message Type  |   UInt16   | Either protocol-level message or user-specified. |
|              2 | Message Flags |   UInt16   | Message Flags                                    |

# Message Types
| ID | Name            |
|:--:|-----------------|
| 0  | Connect         |
| 1  | Reset           |
| 2  | Ping            |
| 3  | Pong            |
| 4  | Get Connections |
| 5  | Connections     |

# Message - Connect
When a node wants to connect, it sends this Message, and the other Node shall respond with a Connect as well.

The Nodes shall maintain a Connect Sent and Connect Received flags.
If Connect Sent, only send out the same Hello Message.
If Connect Received, don't re-send.

If Identical Connection Received again and it does not state it has the Other Connection, re-send the same Connection.
Assume that the other Node had lost our packet.

Shall include a flag that says whether it has the others Connection (Ack)

Don't process Connection Attempts lower than the highest last seen. (Could indicate duplication or out-of-order)

## Message Flags
| Offset (Bits) |     Field Name      |     Field Type     | Description                               |
|--------------:|:-------------------:|:------------------:|-------------------------------------------|
|             0 |      Reserved       | Reserved (11 bits) | Reserved                                  |
|            11 |       Attempt       |       UInt4        | Connection Attempt                        |
|            15 | Received Connection |    Flag (1 bit)    | Wether the Node received our Connection.  |

# Message - Reset

# Message - Ping
When receiving this message, if it is received from a Vague Connection, has a Global Rate Limit. When this is reached, the Server does not respond with a Ping.

If a Ping is sent to a Direct Connection, and not received after 3 attempts, the Connection is demoted to Vague Connection.

Same connection can't claim Global Rate Limit more than once per time slot. Connection will have its own rate limit.

# Message - Get Connections

Nodes will routinely request Connections from its Direct Connections, and even rarer Vague Connections.

# Message - Connection
Chunk of Direct and Vague Connections.

# Extension Header
Likewise with the TCP protocol, we will have a Extension Header of a 32-byte HMAC signature.

# Vague Connections
Vague Connections are connections with Peers that don't require constant pinging, the Network of Vague Connections can be huge, and therfore would be impractical to keep update on them.

There is a timer, that will constantly keep update with **some** of the Vague Connections.

Vague Connections are inbound, when a Node connects to you, it will be considered a Vague Connection.

# Direct Connections
Direct Connections are connections with Peers that require constant pinging / liveness checks for **all** of the Connections, and will regularly exchange information.

The relationship of a Direct Connection between two Nodes are asymmetric, i.e. the other Node doesn't necessarily have to acknowledge the Connection as direct as well.

Direct Connection simply means, that this Node considers this Peer of interest.

If there are not enough Direct Connections, and enough available Vague Connections, attempt to Ping. If respond fast enough, promote.

# Known Peers
Known Peers are IP:Port that are known, but haven't been contacted, they are candidates for Direct Connections.