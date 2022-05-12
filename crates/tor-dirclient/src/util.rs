//! Helper functions for the directory client code

use std::fmt::Write;

/// Encode an HTTP request in a quick and dirty HTTP 1.0 format.
pub(crate) fn encode_request(req: &http::Request<()>) -> String {
    let mut s = format!("{} {} HTTP/1.0\r\n", req.method(), req.uri());

    for (key, val) in req.headers().iter() {
        write!(
            s,
            "{}: {}\r\n",
            key,
            val.to_str()
                .expect("Added an HTTP header that wasn't UTF-8!")
        )
        .unwrap();
    }
    s.push_str("\r\n");
    s
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn format() {
        let req = http::Request::builder()
            .method("GET")
            .uri("/index.html")
            .body(())
            .unwrap();
        assert_eq!(encode_request(&req), "GET /index.html HTTP/1.0\r\n\r\n");
        let req = http::Request::builder()
            .method("GET")
            .uri("/index.html")
            .header("X-Marsupial", "Opossum")
            .body(())
            .unwrap();
        assert_eq!(
            encode_request(&req),
            "GET /index.html HTTP/1.0\r\nx-marsupial: Opossum\r\n\r\n"
        );
    }
}
