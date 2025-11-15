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