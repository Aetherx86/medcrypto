//! A small read-only FHIR search client.
//!
//! The server is trusted with nothing beyond its own data. Each `next` link it returns is checked to be
//! on the same origin before anything is sent to it, so a hostile response cannot use this client to reach
//! internal addresses or collect the bearer token.

use crate::bundle::{parse_bundle, ParsedBundle};
use crate::FhirError;
use std::time::Duration;

const LOINC_SYSTEM: &str = "http://loinc.org";

#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Sent as a bearer token. Keep it out of command lines.
    pub bearer_token: Option<String>,
    pub page_size: u32,
    pub max_pages: u32,
    pub max_page_bytes: u64,
    pub timeout: Duration,
    /// Allow `http://` to something other than the local machine. Patient data would travel in the clear.
    pub allow_insecure_http: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            bearer_token: None,
            page_size: 500,
            max_pages: 1000,
            max_page_bytes: 256 * 1024 * 1024,
            timeout: Duration::from_secs(60),
            allow_insecure_http: false,
        }
    }
}

/// `(scheme, host and port)` of an absolute URL.
fn origin(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    // Credentials in the authority are how a URL hides where it really goes.
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some((scheme.to_ascii_lowercase(), authority.to_ascii_lowercase()))
}

fn is_loopback(authority: &str) -> bool {
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

fn check_endpoint(url: &str, options: &ClientOptions) -> Result<(String, String), FhirError> {
    let (scheme, authority) =
        origin(url).ok_or_else(|| FhirError::Http(format!("not a usable URL: {url}")))?;
    match scheme.as_str() {
        "https" => {}
        "http" if is_loopback(&authority) || options.allow_insecure_http => {}
        _ => {
            return Err(FhirError::Http(format!(
                "refusing {scheme}:// to {authority}: patient data needs https"
            )))
        }
    }
    Ok((scheme, authority))
}

/// The first page's URL for a set of LOINC codes.
pub fn search_url(endpoint: &str, loinc: &[String], page_size: u32) -> String {
    let codes: Vec<String> = loinc
        .iter()
        .map(|c| {
            format!(
                "{}%7C{}",
                LOINC_SYSTEM.replace(':', "%3A").replace('/', "%2F"),
                c
            )
        })
        .collect();
    format!(
        "{}/Observation?code={}&_include=Observation:subject&_count={}",
        endpoint.trim_end_matches('/'),
        codes.join(","),
        page_size
    )
}

/// Follows the search through all of its pages and returns everything merged.
pub fn fetch_observations(
    endpoint: &str,
    loinc: &[String],
    options: &ClientOptions,
) -> Result<ParsedBundle, FhirError> {
    let home = check_endpoint(endpoint, options)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(options.timeout))
        // A redirect would carry the token somewhere that has not been checked.
        .max_redirects(0)
        .build()
        .into();

    let mut merged = ParsedBundle::default();
    let mut next = Some(search_url(endpoint, loinc, options.page_size));
    let mut pages = 0;
    while let Some(url) = next.take() {
        if check_endpoint(&url, options)? != home {
            return Err(FhirError::Http(format!(
                "the server sent a next link to another origin: {url}"
            )));
        }
        pages += 1;
        if pages > options.max_pages {
            return Err(FhirError::Http(format!(
                "more than {} pages",
                options.max_pages
            )));
        }
        let mut request = agent.get(&url).header("Accept", "application/fhir+json");
        if let Some(token) = &options.bearer_token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = request.call().map_err(|e| FhirError::Http(e.to_string()))?;
        let text = response
            .body_mut()
            .with_config()
            .limit(options.max_page_bytes)
            .read_to_string()
            .map_err(|e| FhirError::Http(e.to_string()))?;
        let page = parse_bundle(&text)?;
        next = page.next_link.clone();
        merged.merge(page);
    }
    merged.next_link = None;
    Ok(merged)
}
