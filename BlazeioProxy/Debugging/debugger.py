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