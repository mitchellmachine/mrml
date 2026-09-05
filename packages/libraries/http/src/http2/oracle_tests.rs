//! Live independent-client regressions; enabled explicitly with local TLS fixtures.
//! Python supplies independent TLS/H2 codecs. Rust owns assertions and server behavior.
extern crate std;
use super::*;
use mrml_runtime::TcpListener;
use mrml_tls::TlsServerConfig;
use std::process::Command;
use std::string::ToString;

const ORACLE: &str = r#"
import os,sys,socket,ssl
import h2.connection,h2.config,h2.events
from hyperframe.frame import HeadersFrame,ContinuationFrame,RstStreamFrame
port=int(sys.argv[1]); mode=sys.argv[2]
ctx=ssl.create_default_context(cafile=os.environ['MRML_CA_BUNDLE'])
ctx.minimum_version=ssl.TLSVersion.TLSv1_3
ctx.maximum_version=ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(['h2'])
s=ctx.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost')
s.settimeout(5)
c=h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True,header_encoding='utf-8'))
c.initiate_connection(); s.sendall(c.data_to_send())
base=[(':method','GET'),(':scheme','https'),(':authority','localhost'),(':path','/interop'),('user-agent','independent-h2-completion')]
ended=set(); bodies={}; resets={}; statuses={}
def pump():
    data=s.recv(65536)
    if not data: raise RuntimeError('unexpected EOF')
    for e in c.receive_data(data):
        if isinstance(e,h2.events.ResponseReceived): statuses[e.stream_id]=dict(e.headers)[':status']
        if isinstance(e,h2.events.DataReceived):
            bodies.setdefault(e.stream_id,bytearray()).extend(e.data)
            c.acknowledge_received_data(e.flow_controlled_length,e.stream_id)
        if isinstance(e,h2.events.StreamEnded): ended.add(e.stream_id)
        if isinstance(e,h2.events.StreamReset): resets[e.stream_id]=int(e.error_code)
        if isinstance(e,h2.events.ConnectionTerminated): raise RuntimeError('unexpected GOAWAY '+str(e.error_code))
    pending=c.data_to_send()
    if pending:s.sendall(pending)
def finish(stream):
    while stream not in ended: pump()
    print('response',stream,statuses[stream],len(bodies.get(stream,b'')),bytes(bodies.get(stream,b''))==b'ok',flush=True)
if mode=='legal':
    # Start before receiving SETTINGS, exercising HPACK's initial table size.
    c.send_headers(1,base,end_stream=True)
    raw=c.data_to_send(); block=raw[9:]; split=max(1,len(block)//2)
    first=HeadersFrame(1); first.flags.add('END_STREAM'); first.flags.add('PADDED'); first.flags.add('PRIORITY')
    first.pad_length=7; first.depends_on=0; first.stream_weight=15; first.data=block[:split]
    continuation=ContinuationFrame(1); continuation.flags.add('END_HEADERS'); continuation.data=block[split:]
    def extension_flags(frame):
        b=bytearray(frame.serialize()); b[4]|=128; return b
    s.sendall(extension_flags(first)+extension_flags(continuation)); finish(1)
    post=[(':method','POST')]+base[1:]+[('content-length','120000')]
    c.send_headers(3,post,end_stream=False); s.sendall(c.data_to_send())
    body=b'abc'*40000; at=0
    while at<len(body):
        space=min(c.local_flow_control_window(3)-8,16000,len(body)-at)
        if space<=0: pump(); continue
        c.send_data(3,body[at:at+space],end_stream=at+space==len(body),pad_length=7)
        s.sendall(c.data_to_send()); at+=space
    finish(3)
    c.send_headers(5,base,end_stream=True); s.sendall(c.data_to_send()); finish(5)
elif mode=='fragments':
    c.send_headers(1,base,end_stream=True); raw=c.data_to_send()
    first=HeadersFrame(1); first.flags.add('END_STREAM'); first.data=raw[9:]
    continuation=ContinuationFrame(1)
    s.sendall(first.serialize()+continuation.serialize()*64)
    try:
        while s.recv(65536): pass
    except (ConnectionResetError,ssl.SSLEOFError): pass
    print('bounded-close',flush=True)
elif mode=='localreset':
    c.send_headers(1,[(':method','POST')]+base[1:],end_stream=False)
    c.send_data(1,b'abc',end_stream=False,pad_length=7); s.sendall(c.data_to_send())
    while 1 not in resets:pump()
    print('reset',1,resets[1],flush=True)
    c.send_headers(3,base,end_stream=True); s.sendall(c.data_to_send()); finish(3)
elif mode=='reset':
    c.send_headers(1,[(':method','POST')]+base[1:],end_stream=False)
    c.reset_stream(1,error_code=8)
    c.send_headers(3,base,end_stream=True); s.sendall(c.data_to_send()); finish(3)
elif mode=='excess':
    # Both are opened before SETTINGS arrives; no local max-stream bypass.
    c.send_headers(1,[(':method','POST')]+base[1:],end_stream=False)
    c.send_headers(3,[(':method','POST')]+base[1:],end_stream=False)
    c.send_headers(5,base,end_stream=True)
    c.send_data(3,b'in-flight-before-refusal',end_stream=True)
    s.sendall(c.data_to_send())
    late_reset=RstStreamFrame(3); late_reset.error_code=8; s.sendall(late_reset.serialize())
    c.send_data(1,b'abc',end_stream=True); s.sendall(c.data_to_send())
    finish(1)
    while 3 not in resets or 5 not in resets:pump()
    print('reset',3,resets[3],flush=True); print('reset',5,resets[5],flush=True)
    c.send_headers(7,base,end_stream=True); s.sendall(c.data_to_send()); finish(7)
else: raise RuntimeError('unknown mode')
s.close()
"#;

fn config() -> TlsServerConfig {
    let certificate =
        std::env::var("MRML_HTTP2_HOSTILE_CERT").expect("explicit local leaf fixture");
    let issuer = std::env::var("MRML_HTTP2_HOSTILE_ISSUER").expect("explicit local issuer fixture");
    let key = std::env::var("MRML_HTTP2_HOSTILE_KEY").expect("explicit disposable TLS key");
    let mut chain = mrml_runtime::read_file(&certificate).unwrap();
    chain
        .try_extend_from_slice(&mrml_runtime::read_file(&issuer).unwrap())
        .unwrap();
    TlsServerConfig::from_pem(&chain, &mrml_runtime::read_file(&key).unwrap())
        .unwrap()
        .with_protocols(&["h2"])
        .unwrap()
}

fn run(mode: &'static str) {
    let config = config();
    let python =
        std::env::var("MRML_H2_ORACLE_PYTHON").expect("explicit pinned independent H2 oracle");
    let listener = TcpListener::bind([127, 0, 0, 1], 0).unwrap();
    let port = listener.local_port().unwrap();
    let (accepted, accepted_wait) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if accepted_wait
            .recv_timeout(std::time::Duration::from_secs(6))
            .is_err()
        {
            let _ =
                std::net::TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        }
    });
    let server = std::thread::spawn(move || {
        let socket = listener.accept().unwrap();
        let _ = accepted.send(());
        let tls = TlsServerStream::accept_with_timeout(socket, &config, 5_000).unwrap();
        let mut connection = Http2ServerConnection::accept(tls).unwrap();
        connection
            .stream
            .set_application_io_timeout_millis(5_000)
            .unwrap();
        if mode == "fragments" {
            assert_eq!(connection.next_request(), Err(HttpError::InvalidResponse));
            return;
        }
        if mode == "localreset" {
            let (id, _) = connection.next_request().unwrap();
            assert_eq!(id, 1);
            let mut one = [0; 1];
            assert_eq!(connection.read_request_data(id, &mut one), Ok(1));
            assert_eq!(one, [b'a']);
            connection.reset_stream(id, 8).unwrap();
        }
        if mode == "reset" {
            let (id, _) = connection.next_request().unwrap();
            assert_eq!(id, 1);
            assert_eq!(
                connection.read_request_data(id, &mut [0; 1024]),
                Err(HttpError::Io)
            );
        }
        let ids: &[u32] = match mode {
            "legal" => &[1, 3, 5],
            "reset" | "localreset" => &[3],
            "excess" => &[1, 7],
            _ => unreachable!(),
        };
        for &expected in ids {
            let (id, request) = connection.next_request().unwrap();
            assert_eq!(id, expected);
            assert_eq!(request.target, "/interop");
            let mut body = std::vec::Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let read = connection.read_request_data(id, &mut buffer).unwrap();
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&buffer[..read]);
                assert!(body.len() <= 120_000);
            }
            if request.method == "POST" {
                let repeats = if mode == "legal" { 40000 } else { 1 };
                assert_eq!(body, b"abc".repeat(repeats));
            } else {
                assert!(body.is_empty());
            }
            connection
                .respond(id, 200, &[("content-length", "2")], b"ok")
                .unwrap();
        }
    });
    let output = Command::new(python)
        .arg("-c")
        .arg(ORACLE)
        .arg(port.to_string())
        .arg(mode)
        .output()
        .unwrap();
    assert!(server.join().is_ok(), "live H2 server failed for {mode}");
    assert!(
        output.status.success(),
        "oracle {mode}: {}",
        std::string::String::from_utf8_lossy(&output.stderr)
    );
    let expected = match mode {
        "legal" => "response 1 200 2 True\nresponse 3 200 2 True\nresponse 5 200 2 True\n",
        "reset" => "response 3 200 2 True\n",
        "localreset" => "reset 1 8\nresponse 3 200 2 True\n",
        "fragments" => "bounded-close\n",
        "excess" => "response 1 200 2 True\nreset 3 7\nreset 5 7\nresponse 7 200 2 True\n",
        _ => unreachable!(),
    };
    assert_eq!(
        std::string::String::from_utf8(output.stdout).unwrap(),
        expected
    );
}

#[test]
#[ignore = "requires explicit disposable TLS fixtures and pinned independent Python H2 oracle"]
fn independent_h2_legal_padding_priority_fragmentation_and_flow_control() {
    run("legal");
}
#[test]
#[ignore = "requires explicit disposable TLS fixtures and pinned independent Python H2 oracle"]
fn independent_h2_reset_preserves_connection() {
    run("reset");
}
#[test]
#[ignore = "requires explicit disposable TLS fixtures and pinned independent Python H2 oracle"]
fn independent_h2_excess_stream_is_refused_without_losing_active_stream() {
    run("excess");
}

#[test]
#[ignore = "requires explicit disposable TLS fixtures and pinned independent Python H2 oracle"]
fn independent_h2_local_reset_discards_buffered_body_and_restores_credit() {
    run("localreset");
}
#[test]
#[ignore = "requires explicit disposable TLS fixtures and pinned independent Python H2 oracle"]
fn independent_h2_empty_continuation_flood_is_bounded() {
    run("fragments");
}
