# ./__main__.py
import Blazeio as io
import Blazeio.Other.class_parser as class_parser
from socket import inet_ntoa, inet_aton, inet_ntop, AF_INET6, SOL_SOCKET, IPPROTO_TCP, TCP_NODELAY, SHUT_RDWR, SO_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT

try:
    from socket import SO_REUSEPORT
except ImportError:
    SO_REUSEPORT = None

try:
    from socket import TCP_QUICKACK
except ImportError:
    TCP_QUICKACK = None

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
    __slots__ = ("test", "concurrency", "requests", "url")
    def __init__(app, test: (bool, io.Utype, class_parser.Store) = None, concurrency: (int, io.Utype) = 1, requests: (int, io.Utype) = 1, url: (str, io.Utype) = "https://api.ipify.org/"):
        io.set_from_args(app, locals(), io.Utype)
        io.ioConf.loop.create_task(app.runner())

    async def runner(app):
        await io.Scope.web # Wait for server to start

        async with io.Ehandler(exit_on_err = True, ignore = io.CancelledError):
            await io.gather(*[app.client(str(i)) for i in range(int(app.concurrency))])

        io.getSession.pool().close() # Close all connections in the pool

        await io.sleep(1)

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

    if SO_REUSEPORT:
        io.Scope.web.sock().setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    if TCP_QUICKACK:
        io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_QUICKACK, 1)

    io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    io.Scope.web.sock().setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
    io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 30)
    io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 10)
    io.Scope.web.sock().setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 3)

    with io.Scope.web:
        if parser.args().test:
            Test(**parser.args(Test))
        io.Scope.web.attach(Main(**parser.args(Main)))
        io.Scope.web.runner()

if __name__ == "__main__":
    entry_point()