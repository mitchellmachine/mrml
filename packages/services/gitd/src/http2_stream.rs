use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use mrml_http::{
    BackendError, BoundedRead, BoundedWrite, GitdBackend, GitdHttp3Server, Http2ServerConnection,
    RequestHead,
};

const HTTP2_INTERNAL_ERROR: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp2StreamError {
    Prepare(BackendError),
    Transport,
    Backend(BackendError),
}

trait Http2BodyTransport {
    fn read_data(&mut self, stream_id: u32, output: &mut [u8]) -> Result<usize, ()>;
    fn write_data(&mut self, stream_id: u32, input: &[u8]) -> Result<(), ()>;
    fn finish(&mut self, stream_id: u32) -> Result<(), ()>;
    fn reset(&mut self, stream_id: u32) -> Result<(), ()>;
}

impl Http2BodyTransport for Http2ServerConnection {
    fn read_data(&mut self, stream_id: u32, output: &mut [u8]) -> Result<usize, ()> {
        self.read_request_data(stream_id, output).map_err(|_| ())
    }
    fn write_data(&mut self, stream_id: u32, input: &[u8]) -> Result<(), ()> {
        self.respond_data(stream_id, input, false).map_err(|_| ())
    }
    fn finish(&mut self, stream_id: u32) -> Result<(), ()> {
        self.finish_response(stream_id).map_err(|_| ())
    }
    fn reset(&mut self, stream_id: u32) -> Result<(), ()> {
        self.reset_stream(stream_id, HTTP2_INTERNAL_ERROR)
            .map_err(|_| ())
    }
}

struct Http2Input<'a, T> {
    transport: &'a RefCell<&'a mut T>,
    stream_id: u32,
    remaining: u64,
    draining: &'a AtomicBool,
}

impl<T: Http2BodyTransport> BoundedRead for Http2Input<'_, T> {
    fn remaining(&self) -> u64 {
        self.remaining
    }
    fn read(&mut self, output: &mut [u8]) -> Result<usize, BackendError> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.draining.load(Ordering::Acquire) {
            return Err(BackendError::Storage);
        }
        if self.remaining == 0 {
            return Err(BackendError::ResourceLimit);
        }
        let limit = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(output.len());
        let count = self
            .transport
            .borrow_mut()
            .read_data(self.stream_id, &mut output[..limit])
            .map_err(|_| BackendError::Storage)?;
        self.remaining = self
            .remaining
            .checked_sub(count as u64)
            .ok_or(BackendError::Storage)?;
        Ok(count)
    }
}

struct Http2Output<'a, T> {
    transport: &'a RefCell<&'a mut T>,
    stream_id: u32,
    remaining: u64,
    draining: &'a AtomicBool,
}

impl<T: Http2BodyTransport> BoundedWrite for Http2Output<'_, T> {
    fn remaining(&self) -> u64 {
        self.remaining
    }
    fn write(&mut self, input: &[u8]) -> Result<(), BackendError> {
        if self.draining.load(Ordering::Acquire) {
            return Err(BackendError::Storage);
        }
        let count = u64::try_from(input.len()).map_err(|_| BackendError::ResourceLimit)?;
        if count > self.remaining {
            return Err(BackendError::ResourceLimit);
        }
        self.transport
            .borrow_mut()
            .write_data(self.stream_id, input)
            .map_err(|_| BackendError::Storage)?;
        self.remaining -= count;
        Ok(())
    }
}

pub fn serve_smart_git_http2<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http2ServerConnection,
    stream_id: u32,
    request: &RequestHead,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp2StreamError> {
    let draining = AtomicBool::new(false);
    serve_smart_git_http2_with_drain(
        edge,
        connection,
        stream_id,
        request,
        maximum_body_bytes,
        &draining,
    )
}

fn serve_smart_git_http2_with_drain<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http2ServerConnection,
    stream_id: u32,
    request: &RequestHead,
    maximum_body_bytes: u64,
    draining: &AtomicBool,
) -> Result<(), GitdHttp2StreamError> {
    let input_bytes = exact_receive_body_length(request, maximum_body_bytes)
        .map_err(GitdHttp2StreamError::Prepare)?;
    let (prepared, response) = edge
        .prepare_smart_git(request, input_bytes, maximum_body_bytes)
        .map_err(GitdHttp2StreamError::Prepare)?;
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(response.headers.len())
        .map_err(|_| GitdHttp2StreamError::Transport)?;
    for header in &response.headers {
        headers.push((header.name.as_str(), header.value.as_str()));
    }
    connection
        .respond_head(stream_id, response.status, &headers, false)
        .map_err(|_| GitdHttp2StreamError::Transport)?;

    let transport = RefCell::new(connection);
    let mut input = Http2Input {
        transport: &transport,
        stream_id,
        remaining: input_bytes,
        draining,
    };
    let mut output = Http2Output {
        transport: &transport,
        stream_id,
        remaining: maximum_body_bytes,
        draining,
    };
    match edge.execute_prepared_smart_git(prepared, &mut input, &mut output) {
        Ok(_) => transport
            .borrow_mut()
            .finish(stream_id)
            .map_err(|_| GitdHttp2StreamError::Transport),
        Err(error) => {
            eprintln!(
                "component=mrml-gitd event={}",
                smart_git_backend_event(request, error)
            );
            transport
                .borrow_mut()
                .reset(stream_id)
                .map_err(|_| GitdHttp2StreamError::Transport)?;
            Err(GitdHttp2StreamError::Backend(error))
        }
    }
}

fn smart_git_backend_event(request: &RequestHead, error: BackendError) -> &'static str {
    let operation = if request.method == "GET"
        && request
            .target
            .ends_with("info/refs?service=git-upload-pack")
    {
        "discovery"
    } else if request.method == "GET"
        && request
            .target
            .ends_with("info/refs?service=git-receive-pack")
    {
        "receive_discovery"
    } else if request.method == "POST" && request.target.ends_with("/git-upload-pack") {
        "upload_pack"
    } else {
        "receive_pack"
    };
    match (operation, error) {
        ("discovery", BackendError::Unsupported) => "http2_discovery_unsupported",
        ("receive_discovery", BackendError::Unsupported) => "http2_receive_discovery_unsupported",
        ("upload_pack", BackendError::Unsupported) => "http2_upload_pack_unsupported",
        ("receive_pack", BackendError::Unsupported) => "http2_receive_pack_unsupported",
        ("discovery", _) => "http2_discovery_failed",
        ("receive_discovery", _) => "http2_receive_discovery_failed",
        ("upload_pack", _) => "http2_upload_pack_failed",
        _ => "http2_receive_pack_failed",
    }
}

pub(crate) fn exact_receive_body_length(
    request: &RequestHead,
    maximum: u64,
) -> Result<u64, BackendError> {
    if request.method != "POST" || !request.target.ends_with("/git-receive-pack") {
        return Ok(maximum);
    }
    let mut values = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"));
    let value = values.next().ok_or(BackendError::Unsupported)?;
    if values.next().is_some()
        || value.value.is_empty()
        || (value.value.len() > 1 && value.value.starts_with('0'))
        || !value.value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BackendError::Unsupported);
    }
    value
        .value
        .parse::<u64>()
        .ok()
        .filter(|length| *length != 0 && *length <= maximum)
        .ok_or(BackendError::ResourceLimit)
}

/// Serve requests sequentially on one authenticated HTTP/2 connection. The
/// listener owns connection concurrency; this function owns exact per-stream
/// routing and closes the connection on any ambiguous stream state.
pub fn serve_gitd_http2_connection<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http2ServerConnection,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp2StreamError> {
    let draining = AtomicBool::new(false);
    serve_gitd_http2_connection_with_drain(edge, connection, maximum_body_bytes, &draining)
}

pub fn serve_gitd_http2_connection_with_drain<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http2ServerConnection,
    maximum_body_bytes: u64,
    draining: &AtomicBool,
) -> Result<(), GitdHttp2StreamError> {
    loop {
        if draining.load(Ordering::Acquire) {
            return Ok(());
        }
        let (stream_id, request) = connection
            .next_request()
            .map_err(|_| GitdHttp2StreamError::Transport)?;
        if is_smart_git_target(&request.target) {
            match serve_smart_git_http2_with_drain(
                edge,
                connection,
                stream_id,
                &request,
                maximum_body_bytes,
                draining,
            ) {
                Ok(()) => continue,
                Err(GitdHttp2StreamError::Prepare(error)) => {
                    let status = prepare_error_status(error);
                    connection
                        .respond(stream_id, status, &[("content-length", "0")], b"")
                        .map_err(|_| GitdHttp2StreamError::Transport)?;
                    return Err(GitdHttp2StreamError::Prepare(error));
                }
                Err(error) => return Err(error),
            }
        }

        if !connection
            .request_body_complete(stream_id)
            .map_err(|_| GitdHttp2StreamError::Transport)?
        {
            connection
                .respond(stream_id, 405, &[("content-length", "0")], b"")
                .map_err(|_| GitdHttp2StreamError::Transport)?;
            return Err(GitdHttp2StreamError::Prepare(BackendError::Unsupported));
        }

        let response = edge.handle(&request);
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(response.headers.len())
            .map_err(|_| GitdHttp2StreamError::Transport)?;
        for header in &response.headers {
            headers.push((header.name.as_str(), header.value.as_str()));
        }
        connection
            .respond(stream_id, response.status, &headers, &response.body)
            .map_err(|_| GitdHttp2StreamError::Transport)?;
    }
}

fn is_smart_git_target(target: &str) -> bool {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    path.split('/').any(|component| component.ends_with(".git"))
}

fn prepare_error_status(error: BackendError) -> u16 {
    match error {
        BackendError::NotFound
        | BackendError::MalformedIdentifier
        | BackendError::MalformedPath
        | BackendError::MalformedRevision
        | BackendError::Private => 404,
        BackendError::ResourceLimit => 429,
        _ => 503,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeTransport {
        input: Vec<u8>,
        at: usize,
        output: Vec<u8>,
    }
    impl Http2BodyTransport for FakeTransport {
        fn read_data(&mut self, _stream_id: u32, output: &mut [u8]) -> Result<usize, ()> {
            let count = output.len().min(self.input.len().saturating_sub(self.at));
            output[..count].copy_from_slice(&self.input[self.at..self.at + count]);
            self.at += count;
            Ok(count)
        }
        fn write_data(&mut self, _stream_id: u32, input: &[u8]) -> Result<(), ()> {
            self.output.extend_from_slice(input);
            Ok(())
        }
        fn finish(&mut self, _stream_id: u32) -> Result<(), ()> {
            Ok(())
        }
        fn reset(&mut self, _stream_id: u32) -> Result<(), ()> {
            Ok(())
        }
    }

    #[test]
    fn adapters_share_transport_without_exceeding_exact_limits() {
        let mut fake = FakeTransport {
            input: b"abcdef".to_vec(),
            ..FakeTransport::default()
        };
        let transport = RefCell::new(&mut fake);
        let draining = AtomicBool::new(false);
        let mut input = Http2Input {
            transport: &transport,
            stream_id: 1,
            remaining: 4,
            draining: &draining,
        };
        let mut output = Http2Output {
            transport: &transport,
            stream_id: 1,
            remaining: 3,
            draining: &draining,
        };
        let mut bytes = [0; 8];
        assert_eq!(input.read(&mut bytes).unwrap(), 4);
        assert_eq!(&bytes[..4], b"abcd");
        assert_eq!(input.read(&mut bytes), Err(BackendError::ResourceLimit));
        output.write(b"abc").unwrap();
        assert_eq!(output.write(b"d"), Err(BackendError::ResourceLimit));
        draining.store(true, Ordering::Release);
        assert_eq!(output.write(b""), Err(BackendError::Storage));
        drop(input);
        drop(output);
        assert_eq!(&transport.borrow().output, b"abc");
    }

    #[test]
    fn connection_routing_and_prepare_errors_fail_closed() {
        assert!(is_smart_git_target(
            "/mitchellrenouf/mrml.git/git-upload-pack"
        ));
        assert!(is_smart_git_target(
            "/mitchellrenouf/mrml.git/info/refs?service=git-upload-pack"
        ));
        assert!(!is_smart_git_target("/mitchellrenouf/mrml"));
        assert!(!is_smart_git_target("/mrml.git.example/path"));
        assert_eq!(prepare_error_status(BackendError::Private), 404);
        assert_eq!(prepare_error_status(BackendError::ResourceLimit), 429);
        assert_eq!(prepare_error_status(BackendError::Storage), 503);

        let receive = |values: &[&str]| RequestHead {
            method: "POST".into(),
            scheme: "https".into(),
            authority: "git.example".into(),
            target: "/owner/repository.git/git-receive-pack".into(),
            headers: values
                .iter()
                .map(|value| mrml_http::Header {
                    name: "content-length".into(),
                    value: (*value).into(),
                })
                .collect(),
        };
        assert_eq!(
            exact_receive_body_length(&receive(&["4096"]), 8192),
            Ok(4096)
        );
        assert_eq!(
            exact_receive_body_length(&receive(&[]), 8192),
            Err(BackendError::Unsupported)
        );
        assert_eq!(
            exact_receive_body_length(&receive(&["1", "1"]), 8192),
            Err(BackendError::Unsupported)
        );
        assert_eq!(
            exact_receive_body_length(&receive(&["04096"]), 8192),
            Err(BackendError::Unsupported)
        );
        assert_eq!(
            exact_receive_body_length(&receive(&["8193"]), 8192),
            Err(BackendError::ResourceLimit)
        );
    }
}
