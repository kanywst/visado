use crate::error::AuthError;

/// The parts of an HTTP request authentication looks at.
#[derive(Debug, Clone)]
pub struct RequestView<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// `http` or `https`.
    pub scheme: &'a str,
    /// Host and optional port.
    pub authority: &'a str,
    /// Path, possibly with a query string.
    pub path: &'a str,
    /// Header fields. Names must be lowercase.
    pub headers: &'a [(String, String)],
    /// The request body exactly as received, when the proxy sends it. `None`
    /// when it was not sent, which is treated as an empty body.
    pub body: Option<&'a [u8]>,
    /// The peer's certificate as Envoy reports it in
    /// `CheckRequest.attributes.source.certificate`: URL-encoded PEM. Set only
    /// from the proxy's own TLS termination, never from a request header.
    pub peer_certificate: Option<&'a str>,
}

impl RequestView<'_> {
    /// The WPT audience: scheme, authority and path, without query or fragment.
    #[must_use]
    pub fn audience(&self) -> String {
        let path = self.path.split(['?', '#']).next().unwrap_or("");
        format!("{}://{}{}", self.scheme, self.authority, path)
    }

    /// The value of a header that may appear at most once.
    ///
    /// # Errors
    ///
    /// [`AuthError::RepeatedHeader`] if it appears more than once.
    pub fn single(&self, name: &str) -> Result<Option<&str>, AuthError> {
        let mut values = self
            .headers
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.as_str());
        let first = values.next();
        if values.next().is_some() {
            return Err(AuthError::RepeatedHeader(name.to_owned()));
        }
        Ok(first)
    }
}
