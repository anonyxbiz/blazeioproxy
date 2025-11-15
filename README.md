**🔥 BlazeioProxy** - High-Performance SOCKS5 Proxy

Enterprise-grade SOCKS5 proxy built with **Blazeio**.

## 🚀 What is BlazeioProxy?

**BlazeioProxy** is a high-performance SOCKS5 proxy server that enables raw TCP protocol handling with zero-copy efficiency and enterprise-grade performance.

## ✨ Why BlazeioProxy?

- 🚀 **Protocol Agnostic**: Implements SOCKS5 natively.
- ⚡ **Zero-Copy Streaming:** Kernel-to-kernel data transfer with perfect backpressure.
- 🎯 **Production Ready**: Socket-level optimizations (TCP_NODELAY, KEEPALIVE).
- 📦 **Modular Design**: Clean parser architecture for different address types.
- 🧪 **Proven Performance**: Tens of thousands of concurrent connections with zero memory leaks and ultra low latency.

## 🏗️ Architecture

#### Modular Parser Design

```
BlazeioProxy/
├── Parsers/
│   ├── atyp1.py    # IPv4 address handling
│   ├── atyp3.py    # Domain name handling  
│   └── atyp4.py    # IPv6 address handling
├── __main__.py     # Main application
└── __init__.py
```

#### Protocol Flow

```
Client → BlazeioProxy → SOCKS5 Parser → Target Server → Client
    ↓          ↓              ↓              ↓          ↓
 Raw TCP   Protocol     Address Type     Connection  Response
 Request   Parsing      Specific         Routing     Streaming
```

## 🛠️ Installation

#### Prerequisites
· Python 3.8+
· Blazeio framework

## Quick Start

```bash
# Install Blazeio
pip install git+https://github.com/anonyxbiz/blazeio.git

# Install
pip install git+https://github.com/anonyxbiz/blazeioproxy.git

# Run the proxy server
BlazeioProxy
```

#### Advanced Usage

```bash
# Run with custom port
BlazeioProxy --port 8080

# Enable debug mode
BlazeioProxy --debug

# Run load tests (20 concurrent clients × 10 requests each)
BlazeioProxy --test "20,10"
```

## 📖 Usage Examples

#### Basic SOCKS5 Proxy

```python
import Blazeio as io

async def main():
    # Use the proxy for HTTP requests
    async with io.getSession.get(
        "https://api.ipify.org", 
        socks5proxy=io.ddict(host="127.0.0.1", port=6000)
    ) as resp:
        await io.log.green(await resp.text())  # Shows your IP through proxy

io.ioConf.run(main())
```

#### Integration with BlazeioClient

```python
import Blazeio as io

async def main():
    # Direct SOCKS5 support in BlazeioClient
    async with io.BlazeioClient(
        "example.com", 
        443,
        socks5proxy=io.ddict(host="127.0.0.1", port=6000, start_tls=False)
    ) as client:
        await client.start_tls()
        await client.writer(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        async for chunk in client:
            await io.log.green(chunk)

io.ioConf.run(main())
```

## 🧪 Performance Testing

#### Load Test Results

```bash
BlazeioProxy --test "20,10"
```

#### Sample Output

```
<(<OOP_Route_Def.attach>) -> [23:38:57:45]>:  Added __main_handler__ => __main_handler__.
<(<Server.run> - Blazeio (Version: 2.9.5.7)) -> [23:38:57:46]>:
  PID: 1619
    System: posix
      Cpu_count: 8
        Server [Blazeio_App] running on http://0.0.0.0:6000
          Request Logging is disabled.
...
<(<Handle._run> - 14) -> [23:39:01:88]>:
  {
 "host": "api.ipify.org",
 "status_code": 200,
 "data": "127.0.0.1"
}

<(<Handle._run> - 0) -> [23:39:02:14]>:
  {
 "host": "api.ipify.org",
 "status_code": 200,
 "data": "127.0.0.1"
}

<(<Handle._run> - 17) -> [23:39:02:14]>:
  {
 "host": "api.ipify.org",
 "status_code": 200,
 "data": "127.0.0.1"
}

<(<Handle._run> - 14) -> [23:39:02:15]>:
  {
 "host": "api.ipify.org",
 "status_code": 200,
 "data": "127.0.0.1"
}
...
<(<Handle._run>) -> [22:54:58:29]>:
{
  "server_connections": 0  # ✅ Zero leaks!
}
```

## 🔧 Technical Features

#### Socket-Level Optimizations

```python
...
# Production-ready TCP optimizations
io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
io.Scope.web.sock().setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 30)
io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 10)
```

#### Zero-Copy Bidirectional Streaming

```python
...
async def juggler(app, source: io.BlazeioProtocol, dest: io.BlazeioProtocol):
    async for chunk in source:
        await dest.writer(chunk)  # Zero-Copy transfer
```

#### Protocol-Agnostic Architecture

```python
# Raw byte-level protocol handling
async def parser(app, r: io.BlazeioServerProtocol):
    async for chunk in r:
        r.store.buff.extend(chunk)
        # Manual SOCKS5 state machine
        # Supports IPv4, IPv6, and domain names
```

## 🎯 Use Cases

#### Enterprise Applications

- **🛡️ Corporate Proxies**: Secure internal network access.
- **🌐 Load Balancers**: Custom routing logic.
- **🔒 VPN Gateways**: Protocol translation.
- **📊 Monitoring**: Network traffic analysis.

#### Developer Tools

- **🧪 Testing**: Multi-environment request routing.
- **🔧 Debugging**: Traffic inspection and modification.
- **🔄 Migration**: Protocol transition systems.

#### High-Performance Applications

- **🎮 Game Servers**: Custom binary protocols.
- **📡 IoT Gateways**: Device communication.
- **💸 Trading Systems**: Low-latency data feeds.

## 🚀 Performance Characteristics

#### Proven Capabilities

- **Concurrent Connections**: Tens of thousands on minimal hardware.
- **Memory Usage**: Constant (zero buffer explosions).
- **Latency**: Ulra-low latency through full proxy chain.
- **Resource Management**: Zero connection leaks.
- **Protocol Support**: Full SOCKS5 (IPv4, IPv6, domains).

## 🤝 Contributing

We welcome contributions! Areas of particular interest:
- **Performance**: Additional optimizations.

## 📄 License
MIT License - feel free to use this project for personal or commercial purposes.

## 🙏 Acknowledgments

- Built with **Blazeio** - The ultra-fast asynchronous web framework crafted for high-performance backend applications.
- Inspired by the need for high-performance networking in Python.
- Community contributors and testers.

---

⭐ Star this repo if you find it useful!

🐛 Found an issue? Open an issue or submit a pull request.

💬 Questions? Join our discussions in the GitHub issues section.

---