use super::*;

pub(crate) async fn read_frame<R>(stream: &mut R) -> Result<Vec<u8>, io::Error>
where
    R: AsyncRead + Unpin,
{
    let length = usize::from(stream.read_u16().await?);
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).await?;
    Ok(packet)
}

pub(super) async fn read_frame_with_timeout<R>(
    stream: &mut R,
    timeout: Duration,
) -> Result<Vec<u8>, io::Error>
where
    R: AsyncRead + Unpin,
{
    time::timeout(timeout, read_frame(stream))
        .await
        .map_err(|_| timed_out("reading DNS-over-TCP frame"))?
}

pub(crate) async fn write_frame<W>(stream: &mut W, packet: &[u8]) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    let frame = frame_packet(packet)?;
    stream.write_all(&frame).await
}

pub(super) async fn write_frame_with_timeout<W>(
    stream: &mut W,
    packet: &[u8],
    timeout: Duration,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    time::timeout(timeout, write_frame(stream, packet))
        .await
        .map_err(|_| timed_out("writing DNS-over-TCP frame"))?
}

fn timed_out(operation: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, operation)
}

pub(super) fn frame_packet(packet: &[u8]) -> Result<Vec<u8>, io::Error> {
    // Every packet reaching this function has already been bounded by the wire
    // encoder.
    let length = u16::try_from(packet.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS message exceeds the TCP frame limit",
        )
    })?;
    let mut frame = Vec::with_capacity(packet.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(packet);
    Ok(frame)
}
