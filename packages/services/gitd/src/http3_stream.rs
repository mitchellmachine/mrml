use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use mrml_http::{
    BackendError, BoundedRead, BoundedWrite, GitdBackend, GitdHttp3Server, Http3ServerConnection,
    RequestHead,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitdHttp3StreamError {
    Prepare(BackendError),
    Transport,
    Backend(BackendError),
}

struct Http3Input<'a> {
    connection: &'a RefCell<&'a mut Http3ServerConnection>,
    stream_id: u64,
    remaining: u64,
    draining: &'a AtomicBool,
}

impl BoundedRead for Http3Input<'_> {
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
            .connection
            .borrow_mut()
            .read_request_data(self.stream_id, &mut output[..limit])
            .map_err(|_| BackendError::Storage)?;
        self.remaining = self
            .remaining
            .checked_sub(count as u64)
            .ok_or(BackendError::Storage)?;
        Ok(count)
    }
}

struct Http3Output<'a> {
    connection: &'a RefCell<&'a mut Http3ServerConnection>,
    stream_id: u64,
    remaining: u64,
    draining: &'a AtomicBool,
}

impl BoundedWrite for Http3Output<'_> {
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
        self.connection
            .borrow_mut()
            .respond_data(self.stream_id, input, false)
            .map_err(|_| BackendError::Storage)?;
        self.remaining -= count;
        Ok(())
    }
}

pub fn serve_smart_git_http3<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http3ServerConnection,
    stream_id: u64,
    request: &RequestHead,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp3StreamError> {
    let draining = AtomicBool::new(false);
    serve_smart_git_http3_with_drain(
        edge,
        connection,
        stream_id,
        request,
        maximum_body_bytes,
        &draining,
    )
}

fn serve_smart_git_http3_with_drain<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http3ServerConnection,
    stream_id: u64,
    request: &RequestHead,
    maximum_body_bytes: u64,
    draining: &AtomicBool,
) -> Result<(), GitdHttp3StreamError> {
    let (prepared, response) = edge
        .prepare_smart_git(request, maximum_body_bytes, maximum_body_bytes)
        .map_err(GitdHttp3StreamError::Prepare)?;
    let mut headers = Vec::new();
    headers
        .try_reserve_exact(response.headers.len())
        .map_err(|_| GitdHttp3StreamError::Transport)?;
    for header in &response.headers {
        headers.push((header.name.as_str(), header.value.as_str()));
    }
    connection
        .respond_head(stream_id, response.status, &headers, false)
        .map_err(|_| GitdHttp3StreamError::Transport)?;
    let connection = RefCell::new(connection);
    let mut input = Http3Input {
        connection: &connection,
        stream_id,
        remaining: maximum_body_bytes,
        draining,
    };
    let mut output = Http3Output {
        connection: &connection,
        stream_id,
        remaining: maximum_body_bytes,
        draining,
    };
    let result = edge.execute_prepared_smart_git(prepared, &mut input, &mut output);
    drop(input);
    drop(output);
    match result {
        Ok(_) => {
            let mut connection = connection.borrow_mut();
            if !connection
                .request_body_complete(stream_id)
                .map_err(|_| GitdHttp3StreamError::Transport)?
            {
                return Err(GitdHttp3StreamError::Backend(BackendError::Storage));
            }
            let mut empty = [0; 1];
            if connection
                .read_request_data(stream_id, &mut empty)
                .map_err(|_| GitdHttp3StreamError::Transport)?
                != 0
            {
                return Err(GitdHttp3StreamError::Backend(BackendError::Storage));
            }
            connection
                .finish_response(stream_id)
                .map_err(|_| GitdHttp3StreamError::Transport)
        }
        Err(error) => Err(GitdHttp3StreamError::Backend(error)),
    }
}

pub fn serve_gitd_http3_connection<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http3ServerConnection,
    maximum_body_bytes: u64,
) -> Result<(), GitdHttp3StreamError> {
    let draining = AtomicBool::new(false);
    serve_gitd_http3_connection_with_drain(edge, connection, maximum_body_bytes, &draining)
}

pub fn serve_gitd_http3_connection_with_drain<B: GitdBackend>(
    edge: &mut GitdHttp3Server<B>,
    connection: &mut Http3ServerConnection,
    maximum_body_bytes: u64,
    draining: &AtomicBool,
) -> Result<(), GitdHttp3StreamError> {
    loop {
        if draining.load(Ordering::Acquire) {
            return Ok(());
        }
        let (stream_id, request) = connection
            .next_request()
            .map_err(|_| GitdHttp3StreamError::Transport)?;
        if is_smart_git_target(&request.target) {
            match serve_smart_git_http3_with_drain(
                edge,
                connection,
                stream_id,
                &request,
                maximum_body_bytes,
                draining,
            ) {
                Ok(()) => continue,
                Err(GitdHttp3StreamError::Prepare(error)) => {
                    connection
                        .respond(
                            stream_id,
                            prepare_error_status(error),
                            &[("content-length", "0")],
                            b"",
                        )
                        .map_err(|_| GitdHttp3StreamError::Transport)?;
                    return Err(GitdHttp3StreamError::Prepare(error));
                }
                Err(error) => return Err(error),
            }
        }
        if !connection
            .request_body_complete(stream_id)
            .map_err(|_| GitdHttp3StreamError::Transport)?
        {
            connection
                .respond(stream_id, 405, &[("content-length", "0")], b"")
                .map_err(|_| GitdHttp3StreamError::Transport)?;
            return Err(GitdHttp3StreamError::Prepare(BackendError::Unsupported));
        }
        let mut empty = [0; 1];
        if connection
            .read_request_data(stream_id, &mut empty)
            .map_err(|_| GitdHttp3StreamError::Transport)?
            != 0
        {
            return Err(GitdHttp3StreamError::Transport);
        }
        let response = edge.handle(&request);
        let mut headers = Vec::new();
        headers
            .try_reserve_exact(response.headers.len())
            .map_err(|_| GitdHttp3StreamError::Transport)?;
        for header in &response.headers {
            headers.push((header.name.as_str(), header.value.as_str()));
        }
        connection
            .respond(stream_id, response.status, &headers, &response.body)
            .map_err(|_| GitdHttp3StreamError::Transport)?;
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

    #[test]
    fn route_and_error_mapping_match_http2_concealment() {
        assert!(is_smart_git_target("/owner/repo.git/git-upload-pack"));
        assert!(!is_smart_git_target("/owner/repo"));
        assert_eq!(prepare_error_status(BackendError::Private), 404);
        assert_eq!(prepare_error_status(BackendError::ResourceLimit), 429);
        assert_eq!(prepare_error_status(BackendError::Storage), 503);
    }
}
