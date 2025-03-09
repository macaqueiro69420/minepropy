# MinePropy

A Minecraft protocol proxy that logs command and chat packets.

## Features

- Acts as a proxy between a Minecraft client and server
- Decrypts, decompresses, and parses Minecraft protocol traffic
- Logs all chat messages and commands in detail
- Handles protocol encryption and compression
- Pure Python implementation (no external dependencies except cryptography)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/macaqueiro69420/minepropy.git
   cd minepropy
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

The proxy listens on a specified port and forwards connections to a Minecraft server. By default, it listens on 127.0.0.1:25565 and forwards to 127.0.0.1:25566.

Basic usage:
```
python minecraft_proxy.py
```

Advanced options:
```
python minecraft_proxy.py --listen-host 0.0.0.0 --listen-port 25565 --server-host mc.someserver.com --server-port 25565 --debug
```

### Client Setup

To use the proxy, configure your Minecraft client to connect to the proxy's address instead of the actual server.

For example, if the proxy is running on the same machine as your Minecraft client:
- In Minecraft, connect to `localhost:25565` (or whatever port you configured)
- The proxy will automatically connect to the actual Minecraft server

## How it Works

1. The proxy creates a server socket and waits for connections
2. When a client connects, the proxy establishes a connection to the target Minecraft server
3. The proxy forwards all traffic between client and server, while also:
   - Parsing the Minecraft protocol
   - Handling encryption and compression
   - Logging chat and command packets

## Limitations

- Currently only monitors chat and command packets
- May need updates for new Minecraft protocol versions
- Does not modify packet contents (pure monitoring)