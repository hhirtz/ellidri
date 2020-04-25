//! Asynchronous IRC message reading.
//!
//! This exposes a more robust alternative to tokio's `BufReader`, with better control on how lines
//! are read.

use futures::ready;
use std::{io, marker, mem, pin, task};
use std::future::Future;
use tokio::io::{AsyncBufRead, AsyncRead, BufReader};

const ABUSE_ERR: &str = "Bad client, bad! >:(";
const UTF8_ERR: &str = "This was definitely not UTF-8...";
const TOO_LONG_ERR: &str = "Kyaa! Your message is too long!";

const MAX_READ_PER_MESSAGE: u8 = 4;
const MAX_TAG_LENGTH: usize = 4096;

/// Asynchronous IRC message reader.
pub struct IrcReader<R> {
    inner: BufReader<R>,
    message_max: usize,
}

impl<R: AsyncRead> IrcReader<R> {
    /// Creates a new `IrcReader` with the given maximum length for messages.
    ///
    /// Although `message_max` allows restriction on the message length, `IrcReader` will always
    /// allow lines of `4096 + message_max` bytes if the line starts with `@`.  This is because the
    /// [message tag spec][1] states that tags can occupy up to 4096 bytes.  Thus, `message_max`
    /// designates the maximum length of a message without tags (should default to 512, see RFCs
    /// 1459 and 2812).
    ///
    /// [1]: https://ircv3.net/specs/extensions/message-tags.html
    pub fn new(r: R, message_max: usize) -> Self {
        Self { inner: BufReader::new(r), message_max }
    }

    /// Equivalent of tokio's `AsyncBufReadExt::read_line` for IRC messages.
    ///
    /// Function signature can also be read like so:
    ///
    /// ```rust
    /// async fn read_message(&mut self, buf: &mut String) -> io::Result<usize>
    /// ```
    pub fn read_message<'a>(&'a mut self, buf: &'a mut String) -> ReadMessage<'a, R>
        where Self: marker::Unpin,
    {
        ReadMessage {
            reader: &mut self.inner,
            bytes: unsafe { mem::replace(buf.as_mut_vec(), Vec::new()) },
            buf,
            n: ReadInfo {
                read: 0,
                limit: 0,
                message_max: self.message_max,
                count: 0,
            },
        }
    }
}

#[derive(Debug)]
struct ReadInfo {
    read: usize,
    limit: usize,
    message_max: usize,
    count: u8,
}

/// Future returned by `IrcReader::read_message`.
#[must_use = "futures do nothing unless polled or .await'ed"]
#[derive(Debug)]
pub struct ReadMessage<'a, R> {
    reader: &'a mut BufReader<R>,
    bytes: Vec<u8>,
    buf: &'a mut String,
    n: ReadInfo,
}

impl<R: AsyncRead + marker::Unpin> Future for ReadMessage<'_, R> {
    type Output = io::Result<usize>;

    fn poll(mut self: pin::Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let Self { reader, buf, bytes, n } = &mut *self;
        read_message(pin::Pin::new(reader), cx, buf, bytes, n)
    }
}

fn read_message<R>(reader: pin::Pin<&mut BufReader<R>>, cx: &mut task::Context<'_>,
                   buf: &mut String, bytes: &mut Vec<u8>, n: &mut ReadInfo)
                   -> task::Poll<io::Result<usize>>
    where R: AsyncRead,
{
    let ret = ready!(read_line(reader, cx, bytes, n))?;
    if std::str::from_utf8(&bytes).is_err() {
        task::Poll::Ready(
            Err(io::Error::new(io::ErrorKind::InvalidData, UTF8_ERR))
        )
    } else {
        mem::swap(unsafe { buf.as_mut_vec() }, bytes);
        task::Poll::Ready(Ok(ret))
    }
}

fn read_line<R>(mut reader: pin::Pin<&mut BufReader<R>>, cx: &mut task::Context<'_>,
                bytes: &mut Vec<u8>, n: &mut ReadInfo)
                -> task::Poll<io::Result<usize>>
    where R: AsyncRead,
{
    loop {
        if MAX_READ_PER_MESSAGE <= n.count {
            return task::Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, ABUSE_ERR)));
        }
        if 0 < n.limit && n.limit <= n.read {
            return task::Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, TOO_LONG_ERR)));
        }
        let (done, used) = {
            let available = ready!(reader.as_mut().poll_fill_buf(cx))?;

            if n.limit == 0 && !available.is_empty() {
                if available[0] == b'@' {
                    n.limit = MAX_TAG_LENGTH;
                }
                n.limit += n.message_max;
            }

            if let Some(i) = memchr::memchr2(b'\r', b'\n', available) {
                bytes.extend_from_slice(&available[..=i]);
                if i + 1 < available.len() && available[i + 1] == b'\n' {
                    (true, i + 2)
                } else {
                    (true, i + 1)
                }
            } else {
                bytes.extend_from_slice(available);
                (false, available.len())
            }
        };
        reader.as_mut().consume(used);
        n.read += used;
        if done || used == 0 {
            return task::Poll::Ready(Ok(mem::replace(&mut n.read, 0)));
        }
        n.count += 1;
    }
}
