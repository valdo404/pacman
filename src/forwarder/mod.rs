use bytes::Bytes;
use futures::Stream;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::Request;
use std::error::Error;
use std::pin::Pin;

/// Trait defining the behavior of a request forwarder
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    /// Forward an HTTP request according to the forwarder's strategy
    async fn forward(&self, req: Request<ByteStreamBody>) -> Result<hyper::Response<Full<Bytes>>, Box<dyn Error + Send + Sync>>;
}

mod direct;
mod proxy;

pub use direct::DirectForwarder;
pub use proxy::ProxyForwarder;

pub type ByteStreamBody = StreamBody<Pin<Box<dyn Stream<Item = Result<Frame<Bytes>, Box<dyn Error + Send + Sync>>> + Send + 'static>>>;


pub fn to_transformed_body(
    incoming: Incoming,
) -> ByteStreamBody {
    let stream = incoming.into_data_stream().map(|result| {
        result
            .map(Frame::data)
            .map_err(|enc_err| Box::new(enc_err) as Box<dyn Error + Send + Sync>)
    });

    StreamBody::new(
        Box::pin(stream)
            as Pin<Box<dyn Stream<Item=Result<Frame<Bytes>, Box<dyn Error + Send + Sync>>> + Send>>
    )
}


pub fn convert_request_body<A>(
    req: hyper::Request<A>,
) -> hyper::Request<ByteStreamBody> 
where
    A: hyper::body::Body + Send + 'static,
    A::Data: Into<Bytes>,
    A::Error: Error + Send + Sync + 'static,
{
    let (parts, body) = req.into_parts();
    println!("[PROXY] Request body: {:?}", parts);
    let body_stream = convert_body(body);
    hyper::Request::from_parts(parts, body_stream)
}

pub fn convert_body<A>(body: A) -> ByteStreamBody 
where
    A: hyper::body::Body + Send + 'static,
    A::Data: Into<Bytes>,
    A::Error: Error + Send + Sync + 'static,
{
    let stream = body.into_data_stream().map(|result| {
        result
            .map(|data| Frame::data(data.into()))
            .map_err(|e| Box::new(e) as Box<dyn Error + Send + Sync>)
    });
    StreamBody::new(
        Box::pin(stream)
            as Pin<Box<dyn Stream<Item=Result<Frame<Bytes>, Box<dyn Error + Send + Sync>>> + Send>>
    )
}

