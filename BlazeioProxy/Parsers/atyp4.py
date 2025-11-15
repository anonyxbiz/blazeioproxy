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