# ./setup.py
from setuptools import setup, find_packages

setup(
    name = "BlazeioProxy",
    version = "0.0.4",
    description = "BlazeioProxy is a high-performance SOCKS5 proxy server that enables raw TCP protocol handling with zero-copy efficiency and enterprise-grade performance.",
    license = "MIT",
    author = "Anonyxbiz",
    author_email = "anonyxbiz@gmail.com",
    url = "https://github.com/anonyxbiz/blazeioproxy",
    packages = find_packages(),
    include_package_data = True,
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: MIT",
        "Operating System :: OS Independent",
    ],
    py_modules = ['BlazeioProxy'],
    python_requires = '>=3.6',
    entry_points = {
        'console_scripts': [
            'BlazeioProxy = BlazeioProxy.__main__:entry_point',
        ],
    }
)


# ./BlazeioProxy/__init__.py

# ./BlazeioProxy/__main__.py
# ./__main__.py
import Blazeio as io
import Blazeio.Other.class_parser as class_parser
from socket import inet_ntoa, inet_aton, inet_ntop, AF_INET6, SOL_SOCKET, IPPROTO_TCP, SHUT_RDWR

io.ioConf.OUTBOUND_CHUNK_SIZE, io.ioConf.INBOUND_CHUNK_SIZE = 1024*100, 1024*100
io.Scope.add_imports(globals()) # Add imports to Scope to be shared across modules

io.Scope.web = io.App("0.0.0.0", 6000)

from .Parsers.atyp1 import Parser as atyp1
from .Parsers.atyp3 import Parser as atyp3
from .Parsers.atyp4 import Parser as atyp4
from .Debugging import *

class Rjson:
    __slots__ = ()
    def __init__(app):
        ...

    def rjson(app, r: io.BlazeioServerProtocol):
        return io.anydumps(io.ddict(ip_host = r.ip_host, port = r.ip_port, store = r.store))

class Parsers(atyp1, atyp3, atyp4):
    __slots__ = ()
    def __init__(app):
        io.Super(app).__init__()

    def get(app, key: str, default: any = None):
        return getattr(app, key, default)

class Main(Rjson,):
    __slots__ = ("debug", "auth_required", "port", "identifiers", "parsers")
    confirm_bytes = b'\x05\x00'
    block_hosts = ("0.0.0.0",)
    block_ports = (0,)

    def __init__(app, debug: (bool, io.Utype, class_parser.Store) = False, auth_required: (bool, io.Utype, class_parser.Store) = False, port: (int, io.Utype) = io.Scope.web.ServerConfig.port):
        io.set_from_args(app, locals(), (io.Utype,))
        app.identifiers = 0
        io.Super(app).__init__()
        app.parsers = Parsers()

    async def juggler(app, source: io.BlazeioProtocol, dest: io.BlazeioProtocol):
        try:
            async for chunk in source:
                await dest.writer(chunk)
        except (io.ClientDisconnected, io.Eof, io.ServerDisconnected, io.CloseConnection):
            ...

    def validate(app, r: io.BlazeioServerProtocol):
        if r.store.host in app.block_hosts or r.store.port in app.block_ports:
            raise io.Err("Host blocked")

    async def handle(app, r: io.BlazeioServerProtocol):
        app.identifiers += 1
        r.identifier = app.identifiers
        r.__perf_counter__ = io.perf_counter()

        if not app.debug:
            app.validate(r)
        else:
            Debugger.validate(r)
        
        try:
            async with io.BlazeioClient(host = r.store.host, port = r.store.port) as server:
                # Once connected, notify client of the connection establishment
                await r.writer(r.store.response)

                if app.debug:
                    r.store.debugger = Debugger(r, server)
                    await r.store.debugger.debug()
                    juggler = r.store.debugger.juggler
                else:
                    juggler = app.juggler

                task = io.create_task(juggler(r, server)) # Create a task for moving bytes from server to client
                try:
                    await juggler(server, r) # Await movement of bytes from client to server directly in this connection task
                finally:
                    if not task.done():
                        task.cancel()
        except (OSError,):
            return

    async def parser(app, r: io.BlazeioServerProtocol):
        async for chunk in r:
            r.store.buff.extend(chunk)
            if len(r.store.buff) >= 2:
                if not r.store.ver or not r.store.nmethods:
                    r.store.ver, r.store.nmethods = r.store.buff[0], int(r.store.buff[1])
                    if r.store.ver != 5: 
                        return

            if len(r.store.buff) >= (2 + r.store.nmethods):
                r.store.methods = r.store.buff[2:2+r.store.nmethods]
                r.store.buff = io.memarray(r.store.buff[(2 + r.store.nmethods):])
                break

        if not r.store.methods:
            raise io.Err("Unidentified request: %s" % app.rjson(r))

        r.prepend(r.store.buff[:])
        r.store.buff.clear()

        await r.writer(app.confirm_bytes)

        async for chunk in r:
            r.store.buff.extend(chunk)
            if len(r.store.buff) < 5: continue
            r.store.ver, r.store.cmd, r.store.rsv, r.store.atyp = r.store.buff[0], r.store.buff[1], r.store.buff[2], r.store.buff[3]
            break

        if not (parser := app.parsers.get("atyp%s" % int(r.store.atyp))):
            raise io.Err("Unknown address type: %s" % app.rjson(r))

        r.prepend(r.store.buff[:])
        r.store.buff.clear()

        await parser(r)

    async def handler(app, r: io.BlazeioServerProtocol):
        r.store = io.ddict(buff = io.memarray(), ver = 0, nmethods = 0, methods = 0, host = 0, port = 0, response = 0, atyp = 0)

        await app.parser(r)

        if not r.response:
            raise io.Err("Unidentified request: %s" % app.rjson(r))

        await app.handle(r)

    async def __main_handler__(app, r: io.BlazeioServerProtocol):
        async with io.Ehandler(ignore = (io.CancelledError, io.Eof, io.ServerDisconnected, io.ClientDisconnected, OSError)):
            await app.handler(r)

class Test:
    def __init__(app, test: (bool, io.Utype, class_parser.Store) = None, testclient: (bool, io.Utype, class_parser.Store) = None, concurrency: (int, io.Utype) = 1, requests: (int, io.Utype) = 1, url: (str, io.Utype) = "http://127.0.0.1:6050"):
        io.set_from_args(app, locals(), io.Utype)

        io.ioConf.loop.create_task(app.run_test_srv())

        if app.testclient:
            io.ioConf.loop.create_task(app.runner())

    async def create_srv(app):
        app.test_server = io.App((host := app.url[app.url.find("://") + 3:].split(":"))[0], int(host[1]), with_keepalive = True)

        @app.test_server.add_route
        async def _(r: io.BlazeioProtocol):
            await r.writer(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-length: %d\r\n\r\n%b' % (len(data := r.ip_host), data.encode()))

    async def run_test_srv(app):
        await app.create_srv()
        
        io.TCPOptimizer(app.test_server, so_reuseport = True)

        srv_task = io.create_task(app.test_server.run())
        
        io.Scope.web.on_exit_middleware(app.test_server.shutdown)

        await app.test_server

    async def runner(app):
        await io.Scope.web # Wait for server to start

        async with io.Ehandler(exit_on_err = True, ignore = io.CancelledError):
            await io.gather(*[app.client(str(i)) for i in range(int(app.concurrency))])

        io.getSession.pool().close() # Close all connections in the pool

        # Check if server has connections after closing all
        await io.plog.yellow(io.anydumps(io.ddict(server_connections = len([task for task in io.all_tasks(loop = io.ioConf.loop) if hasattr(task, "__BlazeioProtocol__")])))) # Log all active connections in the server

        await io.Scope.web.exit(terminate = True) # Close server

    async def client(app, task_id: str):
        for i in range(int(app.requests)):
            # Send keepalive requests through the proxy
            async with io.getSession.get(app.url, socks5proxy = io.ddict(host = "127.0.0.1", port = io.Scope.web.ServerConfig.port)) as resp:
                await io.plog.green(task_id, io.anydumps(io.ddict(host = resp.host, status_code = resp.status_code, data = await resp.data()), indent = 1))

def entry_point():
    parser = class_parser.Parser((Main, Test), io.Utype)

    io.Scope.web.ServerConfig.port = int(parser.args().port)
    
    io.TCPOptimizer(io.Scope.web, so_reuseport = True)

    with io.Scope.web:
        if parser.args().test:
            Test(**parser.args(Test))
        io.Scope.web.attach(Main(**parser.args(Main)))
        io.Scope.web.runner()

if __name__ == "__main__":
    entry_point()
# ./BlazeioProxy/Debugging/__init__.py
from .debugger import *

if __name__ == "__main__":
    ...
# ./BlazeioProxy/Debugging/debugger.py
# ./Parsers/debugger.py
import Blazeio as io
import struct

class Parser:
    __slots__ = ("r", "resp", "buff", "raw_buff", "tls_version", "client_random", "cipher_suites", "sni_host")
    def __init__(app, r: io.BlazeioServerProtocol, resp: io.BlazeioClient):
        app.raw_buff, app.buff, app.r, app.resp = bytearray(), bytearray(), r, resp
    
    def data(app):
        return io.ddict({key: str(getattr(app, key, None)) for key in app.__slots__ if key not in ("buff", "raw_buff", "r", "resp")})

    async def tls_client_hello(app):
        r = app.r
        async for chunk in r:
            app.buff.extend(chunk)
            app.raw_buff.extend(chunk)

            # Need at least 5 bytes to read basic TLS header
            if len(app.buff) < 5:
                continue
                
            # Parse TLS Record Header
            content_type = app.buff[0]
            version = app.buff[1:3]
            length = struct.unpack('>H', app.buff[3:5])[0]
            
            # Check if we have complete record
            if len(app.buff) < 5 + length:
                continue
                
            # Verify this is a Handshake record
            if content_type != 0x16:  # Handshake
                app.buff = app.buff[5 + length:]
                continue
                
            # Parse Handshake Header
            handshake_type = app.buff[5]
            handshake_length = struct.unpack('>I', b'\x00' + app.buff[6:9])[0]
            
            # Verify this is Client Hello
            if handshake_type != 0x01:  # Client Hello
                app.buff = app.buff[5 + length:]
                continue

            # Parse Client Hello
            client_hello_start = 9
            client_version = app.buff[client_hello_start:client_hello_start+2]
            client_hello_start += 2
            
            # Client Random (32 bytes)
            client_random = app.buff[client_hello_start:client_hello_start+32]
            client_hello_start += 32
            
            # Session ID Length
            session_id_len = app.buff[client_hello_start]
            client_hello_start += 1
            session_id = app.buff[client_hello_start:client_hello_start+session_id_len]
            client_hello_start += session_id_len
            
            # Cipher Suites Length
            cipher_suites_len = struct.unpack('>H', app.buff[client_hello_start:client_hello_start+2])[0]
            client_hello_start += 2
            cipher_suites = app.buff[client_hello_start:client_hello_start+cipher_suites_len]
            client_hello_start += cipher_suites_len
            
            # Compression Methods Length
            compression_len = app.buff[client_hello_start]
            client_hello_start += 1
            compression_methods = app.buff[client_hello_start:client_hello_start+compression_len]
            client_hello_start += compression_len
            
            # Extensions Length
            if client_hello_start < len(app.buff):
                extensions_len = struct.unpack('>H', app.buff[client_hello_start:client_hello_start+2])[0]
                client_hello_start += 2
                
                # Parse Extensions
                extensions_end = client_hello_start + extensions_len
                sni_host = None
                
                while client_hello_start + 4 <= extensions_end:
                    ext_type = struct.unpack('>H', app.buff[client_hello_start:client_hello_start+2])[0]
                    ext_len = struct.unpack('>H', app.buff[client_hello_start+2:client_hello_start+4])[0]
                    
                    # Server Name Indication (type 0)
                    if ext_type == 0 and ext_len > 5:
                        # Skip extension header and list length
                        sni_data = app.buff[client_hello_start+6:client_hello_start+4+ext_len]
                        if sni_data:
                            name_type = sni_data[0]
                            if name_type == 0:  # host_name
                                name_len = struct.unpack('>H', sni_data[1:3])[0]
                                sni_host = sni_data[3:3+name_len].decode('ascii', errors='ignore')
                                app.sni_host = sni_host
                    
                    client_hello_start += 4 + ext_len

            app.tls_version = struct.unpack(">H", client_version)
            app.client_random = client_random
            app.cipher_suites = cipher_suites
            app.sni_host = sni_host
            app.buff = app.buff[5 + length:]
            break

class Debugger:
    __slots__ = ("r", "resp")
    def __init__(app, r: io.BlazeioServerProtocol, resp: io.BlazeioClient):
        app.r, app.resp = r, resp

    async def juggler(app, source: io.BlazeioProtocol, dest: io.BlazeioProtocol):
        async for chunk in source:
            # await io.plog.yellow(app.r.ip_host, type(source), chunk)
            await dest.writer(chunk)

    async def debug(app):
        parser = Parser(app.r, app.resp)
        await parser.tls_client_hello()
        await io.plog.green(app.r.ip_host, io.anydumps(parser.data(), indent=1))
        app.r.prepend(parser.raw_buff)
    
    @classmethod
    def validate(app, r: io.BlazeioServerProtocol):
        ...

if __name__ == "__main__":
    ...
# ./BlazeioProxy/Parsers/__init__.py

# ./BlazeioProxy/Parsers/atyp1.py
# ./Parsers/atyp1.py
import Blazeio as io

class Parser:
    def __init__(app):
        ...

    async def atyp1(app, r: io.BlazeioServerProtocol):
        while (chunk := await r):
            r.store.buff.extend(chunk)
            if len(r.store.buff) < 10: continue
            ip_bytes = r.store.buff[4:8]
            r.store.host = io.Scope.inet_ntoa(ip_bytes)
            r.store.port = int.from_bytes(r.store.buff[8:10], 'big')
            r.store.response = b"\x05\x00\x00\x01" + ip_bytes + r.store.port.to_bytes(2, 'big')
            r.store.buff = r.store.buff[10:]
            break

if __name__ == "__main__":
    ...
# ./BlazeioProxy/Parsers/atyp3.py
# ./Parsers/atyp3.py
import Blazeio as io

class Parser:
    def __init__(app):
        ...

    async def atyp3(app, r: io.BlazeioServerProtocol):
        while (chunk := await r):
            r.store.buff.extend(chunk)
            if len(r.store.buff) < 5: continue

            if len(r.store.buff) < (total_length_needed := (5 + (domain_length := r.store.buff[4]) + 2)): continue

            r.store.host = (domain_bytes := r.store.buff[5:5+domain_length]).decode()

            r.store.port = int.from_bytes(r.store.buff[(port_start := (5 + domain_length)):port_start+2], 'big')

            r.store.response = b"\x05\x00\x00\x03" + bytes([domain_length]) + domain_bytes + r.store.port.to_bytes(2, 'big')
            r.store.buff = r.store.buff[total_length_needed:]
            break

if __name__ == "__main__":
    ...
# ./BlazeioProxy/Parsers/atyp4.py
# ./Parsers/atyp4.py
import Blazeio as io

class Parser:
    def __init__(app):
        ...

    async def atyp4(app, r: io.BlazeioServerProtocol):
        while (chunk := await r):
            r.store.buff.extend(chunk)
            if len(r.store.buff) < 22: continue
            ip_bytes = r.store.buff[4:20]
            r.store.host = io.Scope.inet_ntop(io.Scope.AF_INET6, ip_bytes)
            r.store.port = int.from_bytes(r.store.buff[20:22], 'big')
            r.store.response = b"\x05\x00\x00\x04" + ip_bytes + r.store.port.to_bytes(2, 'big')
            r.store.buff = r.store.buff[22:]
            break

if __name__ == "__main__":
    ...
# ./BlazeioProxy/Versioning/__init__.py
__version__ = "0.0.4"
