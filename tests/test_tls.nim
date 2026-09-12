## TLS listeners: compile with -d:ssl.
##
## A self-signed P-256 certificate for localhost, valid until 2126, in the
## SEC 1 "EC PRIVATE KEY" form (what `openssl ec` writes) so the loader is
## exercised on the same shape FrameOS hands it. Regenerate with:
##   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
##     -keyout key.pem -out cert.pem -days 36500 -subj "/CN=localhost" \
##     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
##   openssl ec -in key.pem -out key-ec.pem

import std/[httpclient, net, os, strutils], mummy

const
  testCert = """-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIUZamAN7dinEGglG7utfMsGMaoY5swCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkxMjEyMjAwMFoYDzIxMjYwODE5
MTIyMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAASMI/JAkpfQaY6MDcq29H17JILDjmU+ewB91LvQhsxdpaE5OaszaSUA
ZNK9QzwNkdAzyY1K0TAToIc5i46mQGm7o28wbTAdBgNVHQ4EFgQUJ4P/LWfu8ZcB
SLelGeRgm5ioawQwHwYDVR0jBBgwFoAUJ4P/LWfu8ZcBSLelGeRgm5ioawQwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDRwAwRAIgId13ZagrbcVFwPpJKQoawNrBB0m0zXb9UAKYErVrt+gCIBvt
ed4IFxd0P+pnRIL9P6rkTp35FXAiA3YX696h4QuJ
-----END CERTIFICATE-----
"""
  testKey = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJyAmtKAVs7XPLTMJD7guygpiNJd3O9y2MtywgoTnARroAoGCCqGSM49
AwEHoUQDQgAEjCPyQJKX0GmOjA3KtvR9eySCw45lPnsAfdS70IbMXaWhOTmrM2kl
AGTSvUM8DZHQM8mNStEwE6CHOYuOpkBpuw==
-----END EC PRIVATE KEY-----
"""
  plainPort = 8091
  tlsPort = 8092
  bigBodyLen = 4 * 1024 * 1024 # Well past any socket buffer

proc handler(request: Request) =
  case request.uri:
  of "/":
    var headers: mummy.HttpHeaders
    headers["Content-Type"] = "text/plain"
    request.respond(200, headers, "Hello, World!")
  of "/secure":
    request.respond(200, emptyHttpHeaders(), $request.secure)
  of "/echo":
    request.respond(200, emptyHttpHeaders(), request.body)
  of "/big":
    var body = newString(bigBodyLen)
    for i in 0 ..< body.len:
      body[i] = char(ord('a') + (i mod 26))
    var headers: mummy.HttpHeaders
    headers["Content-Type"] = "application/octet-stream"
    request.respond(200, headers, body)
  of "/ws":
    let websocket = request.upgradeToWebSocket()
    websocket.send("hello from " & (if request.secure: "wss" else: "ws"))
  else:
    request.respond(404)

proc websocketHandler(
  websocket: WebSocket,
  event: WebSocketEvent,
  message: Message
) =
  case event:
  of MessageEvent:
    websocket.send("echo " & message.data, message.kind)
  else:
    discard

proc noVerify(): SslContext =
  newContext(verifyMode = CVerifyNone)

proc tlsSocket(port: int): Socket =
  result = newSocket()
  noVerify().wrapSocket(result)
  result.connect("localhost", Port(port))

proc readHttpResponse(socket: Socket): tuple[status: string, headers: string, body: string] =
  var headers = ""
  while true:
    let line = socket.recvLine(timeout = 5000)
    if line.len == 0 or line == "\r\n":
      break
    headers &= line & "\n"
  result.headers = headers
  result.status = headers.splitLines()[0]
  var contentLength = 0
  for line in headers.splitLines():
    if line.toLowerAscii().startsWith("content-length:"):
      contentLength = parseInt(line.split(':', 1)[1].strip())
  if contentLength > 0:
    result.body = socket.recv(contentLength, timeout = 5000)

proc websocketRoundTrip(socket: Socket, secure: bool) =
  socket.send(
    "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n" &
    "Upgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" &
    "Sec-WebSocket-Version: 13\r\n\r\n"
  )
  let upgrade = socket.readHttpResponse()
  doAssert upgrade.status.startsWith("HTTP/1.1 101"), upgrade.status
  doAssert upgrade.headers.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

  proc readFrame(): string =
    let header = socket.recv(2, timeout = 5000)
    doAssert header.len == 2
    doAssert (header[0].uint8 and 0x0f) == 0x1 # Text
    let payloadLen = (header[1].uint8 and 0x7f).int
    doAssert payloadLen <= 125
    socket.recv(payloadLen, timeout = 5000)

  doAssert readFrame() == "hello from " & (if secure: "wss" else: "ws")

  # A masked client frame, as the RFC requires
  let payload = "ping over tls"
  var frame = ""
  frame.add(char(0x81))
  frame.add(char(0x80 or payload.len.uint8))
  let mask = [0x12'u8, 0x34, 0x56, 0x78]
  for b in mask:
    frame.add(char(b))
  for i, c in payload:
    frame.add(char(c.uint8 xor mask[i mod 4]))
  socket.send(frame)
  doAssert readFrame() == "echo " & payload

let
  tls = newTlsConfig(testCert, testKey)
  server = newServer(handler, websocketHandler)

discard server.addListener(Port(plainPort), "localhost")
let tlsListener = server.addListener(Port(tlsPort), "localhost", tls)
doAssert tlsListener.secure
doAssert tlsListener.port == Port(tlsPort)

var requesterThread: Thread[void]

proc requesterBody() =
  server.waitUntilReady()

  block: # Bad certificate material is refused up front
    doAssertRaises(MummyError):
      discard newTlsConfig("not a certificate", testKey)
    doAssertRaises(MummyError):
      discard newTlsConfig(testCert, "not a key")
    doAssertRaises(MummyError):
      discard newTlsConfig("", "")

  block: # GET over TLS
    let client = newHttpClient(sslContext = noVerify())
    doAssert client.getContent("https://localhost:" & $tlsPort & "/") == "Hello, World!"

  block: # POST over TLS with a body
    let client = newHttpClient(sslContext = noVerify())
    let body = "x".repeat(100_000)
    let response = client.post("https://localhost:" & $tlsPort & "/echo", body)
    doAssert response.status.startsWith("200")
    doAssert response.body == body

  block: # Plain and TLS listeners at once, Request.secure tells them apart
    let plain = newHttpClient()
    doAssert plain.getContent("http://localhost:" & $plainPort & "/secure") == "false"
    let secure = newHttpClient(sslContext = noVerify())
    doAssert secure.getContent("https://localhost:" & $tlsPort & "/secure") == "true"

  block: # A response far larger than the socket buffer (partial SSL_write)
    let client = newHttpClient(sslContext = noVerify())
    let body = client.getContent("https://localhost:" & $tlsPort & "/big")
    doAssert body.len == bigBodyLen
    doAssert body[0] == 'a' and body[25] == 'z' and body[26] == 'a'
    doAssert body[^1] == char(ord('a') + ((bigBodyLen - 1) mod 26))

  block: # Several requests on one keep-alive TLS connection
    let client = newHttpClient(sslContext = noVerify())
    for i in 0 ..< 20:
      doAssert client.getContent("https://localhost:" & $tlsPort & "/secure") == "true"

  block: # WebSocket over TLS and over plain
    let secure = tlsSocket(tlsPort)
    secure.websocketRoundTrip(secure = true)
    secure.close()
    let plain = newSocket()
    plain.connect("localhost", Port(plainPort))
    plain.websocketRoundTrip(secure = false)
    plain.close()

  block: # A client that stalls mid-handshake must not block the loop
    let stalled = newSocket()
    stalled.connect("localhost", Port(tlsPort))
    # The first five bytes of a TLS record header, then silence
    stalled.send("\x16\x03\x01\x02\x00")
    let silent = newSocket()
    silent.connect("localhost", Port(tlsPort))
    let client = newHttpClient(sslContext = noVerify())
    doAssert client.getContent("https://localhost:" & $tlsPort & "/") == "Hello, World!"
    let plain = newHttpClient()
    doAssert plain.getContent("http://localhost:" & $plainPort & "/") == "Hello, World!"
    stalled.close()
    silent.close()

  block: # Plain text sent to the TLS port is rejected without harm
    let junk = newSocket()
    junk.connect("localhost", Port(tlsPort))
    junk.send("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    var got = ""
    try:
      got = junk.recv(1024, timeout = 2000)
    except CatchableError:
      discard
    doAssert not got.startsWith("HTTP/1.1 200")
    junk.close()
    let client = newHttpClient(sslContext = noVerify())
    doAssert client.getContent("https://localhost:" & $tlsPort & "/") == "Hello, World!"

  block: # Listeners added and removed while serving
    let extra = server.addListener(Port(0), "localhost")
    doAssert extra.port != Port(0)
    doAssert not extra.secure
    let client = newHttpClient()
    doAssert client.getContent("http://localhost:" & $extra.port.int & "/secure") == "false"
    let extraTls = server.addListener(Port(0), "localhost", tls)
    let secure = newHttpClient(sslContext = noVerify())
    doAssert secure.getContent("https://localhost:" & $extraTls.port.int & "/secure") == "true"

    server.removeListener(extra)
    server.removeListener(extraTls)
    # The loop applies the removal on its next wake-up; a request to a
    # still-open listener gets served, so poll until the port refuses.
    var refused = false
    for attempt in 0 ..< 100:
      let probe = newSocket()
      try:
        probe.connect("localhost", Port(extra.port.int), timeout = 1000)
        probe.close()
        sleep(20)
      except OSError:
        refused = true
        break
    doAssert refused
    # The original listeners are unaffected
    doAssert client.getContent("http://localhost:" & $plainPort & "/secure") == "false"
    doAssert secure.getContent("https://localhost:" & $tlsPort & "/secure") == "true"

  echo "Done, shut down the server"
  server.close()

proc requesterProc() =
  {.cast(gcsafe).}: # tls and server are read-only globals here
    requesterBody()

createThread(requesterThread, requesterProc)

server.serve()
