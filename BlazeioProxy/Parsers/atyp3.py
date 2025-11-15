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