use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
use vanta_runtime::{RuntimeError, Transport};
use vanta_wire::{BASE_HEADER_LEN, BaseHeader, Frame};

pub struct FramedIoTransport<T> {
    io: T,
    kind: &'static str,
}

impl<T> FramedIoTransport<T> {
    pub fn new(io: T, kind: &'static str) -> Self {
        Self { io, kind }
    }
}

async fn read_frame_from_io<T>(io: &mut T) -> Result<Frame, RuntimeError>
where
    T: AsyncRead + Unpin + Send,
{
    let mut header_bytes = [0u8; BASE_HEADER_LEN];
    io.read_exact(&mut header_bytes)
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))?;
    let header = BaseHeader::decode(&header_bytes)?;
    let remaining_len = header.frame_length as usize - BASE_HEADER_LEN;
    let mut rest = vec![0u8; remaining_len];
    io.read_exact(&mut rest)
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))?;
    let mut full = BytesMut::with_capacity(header.frame_length as usize);
    full.extend_from_slice(&header_bytes);
    full.extend_from_slice(&rest);
    Ok(Frame::decode(&full)?)
}

async fn write_frame_to_io<T>(io: &mut T, frame: &Frame) -> Result<(), RuntimeError>
where
    T: AsyncWrite + Unpin + Send,
{
    let bytes = frame.encode()?;
    io.write_all(&bytes)
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))?;
    io.flush()
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))
}

#[async_trait]
impl<T> Transport for FramedIoTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, frame: &Frame) -> Result<(), RuntimeError> {
        write_frame_to_io(&mut self.io, frame).await
    }

    async fn recv(&mut self) -> Result<Frame, RuntimeError> {
        read_frame_from_io(&mut self.io).await
    }

    fn kind(&self) -> &'static str {
        self.kind
    }
}

pub type TcpTransport = FramedIoTransport<TcpStream>;
pub type UnixSocketTransport = FramedIoTransport<UnixStream>;

pub struct WebSocketTransport<S> {
    inner: WebSocketStream<S>,
}

impl<S> WebSocketTransport<S> {
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<S> Transport for WebSocketTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, frame: &Frame) -> Result<(), RuntimeError> {
        let bytes = frame.encode()?;
        self.inner
            .send(Message::Binary(bytes.to_vec().into()))
            .await
            .map_err(|error| RuntimeError::Transport(error.to_string()))
    }

    async fn recv(&mut self) -> Result<Frame, RuntimeError> {
        while let Some(message) = self.inner.next().await {
            let message = message.map_err(|error| RuntimeError::Transport(error.to_string()))?;
            if let Message::Binary(bytes) = message {
                return Frame::decode(&bytes).map_err(RuntimeError::from);
            }
        }
        Err(RuntimeError::Transport("websocket closed".into()))
    }

    fn kind(&self) -> &'static str {
        "websocket"
    }
}

pub struct RelayTransport<T> {
    inner: T,
}

impl<T> RelayTransport<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl<T> Transport for RelayTransport<T>
where
    T: Transport,
{
    async fn send(&mut self, frame: &Frame) -> Result<(), RuntimeError> {
        self.inner.send(frame).await
    }

    async fn recv(&mut self) -> Result<Frame, RuntimeError> {
        self.inner.recv().await
    }

    fn kind(&self) -> &'static str {
        "relay"
    }
}

pub async fn accept_websocket(
    stream: TcpStream,
) -> Result<WebSocketTransport<TcpStream>, RuntimeError> {
    let websocket = accept_async(stream)
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))?;
    Ok(WebSocketTransport::new(websocket))
}

pub async fn bind_tcp(addr: &str) -> Result<TcpListener, RuntimeError> {
    TcpListener::bind(addr)
        .await
        .map_err(|error| RuntimeError::Transport(error.to_string()))
}

pub async fn bind_unix(path: &str) -> Result<UnixListener, RuntimeError> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).map_err(|error| RuntimeError::Transport(error.to_string()))
}
