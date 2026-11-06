//! The client against a real socket: a minimal server that answers with canned pages.

use medcrypto_fhir::client::{fetch_observations, search_url, ClientOptions};
use medcrypto_fhir::FhirError;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// Serves one response per request, in order, and records what it was asked.
fn serve(responses: Vec<(u16, String)>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
                request.push_str(&line);
            }
            log.lock().unwrap().push(request);
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/fhir+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    (format!("http://127.0.0.1:{port}/fhir/R4"), seen)
}

fn page(value: f64, next: Option<String>) -> String {
    let link = next
        .map(|url| serde_json::json!([{"relation": "next", "url": url}]))
        .unwrap_or_else(|| serde_json::json!([]));
    serde_json::json!({"resourceType": "Bundle", "link": link, "entry": [{"resource": {
        "resourceType": "Observation", "id": "o", "status": "final",
        "code": {"coding": [{"system": "http://loinc.org", "code": "2339-0"}]},
        "subject": {"reference": "Patient/a"}, "effectiveDateTime": "2026-01-01",
        "valueQuantity": {"value": value, "code": "mg/dL"}
    }}]})
    .to_string()
}

fn codes() -> Vec<String> {
    vec!["2339-0".to_string()]
}

#[test]
fn builds_the_search_and_sends_the_token() {
    let (endpoint, seen) = serve(vec![(200, page(100.0, None))]);
    let options = ClientOptions {
        bearer_token: Some("test-token".into()),
        ..ClientOptions::default()
    };
    let parsed = fetch_observations(&endpoint, &codes(), &options).unwrap();
    assert_eq!(parsed.observations.len(), 1);
    let log = seen.lock().unwrap();
    assert!(
        log[0].contains("GET /fhir/R4/Observation?code=http%3A%2F%2Floinc.org%7C2339-0"),
        "{}",
        log[0]
    );
    assert!(log[0].contains("_include=Observation:subject"));
    assert!(log[0]
        .to_lowercase()
        .contains("authorization: bearer test-token"));
}

#[test]
fn walks_through_every_page_on_the_same_origin() {
    // The second page's address is only known once the port is, so the first page is built around it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = format!("http://127.0.0.1:{port}/fhir");
    let first = page(100.0, Some(format!("{endpoint}/next?page=2")));
    let second = page(110.0, None);
    std::thread::spawn(move || {
        for body in [first, second] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                line.clear();
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let parsed = fetch_observations(&endpoint, &codes(), &ClientOptions::default()).unwrap();
    assert_eq!(parsed.observations.len(), 2);
    assert!(parsed.next_link.is_none());
}

#[test]
fn a_next_link_to_another_host_is_refused_before_anything_is_sent() {
    let (endpoint, seen) = serve(vec![(
        200,
        page(100.0, Some("https://attacker.example/steal".into())),
    )]);
    let options = ClientOptions {
        bearer_token: Some("test-token".into()),
        ..ClientOptions::default()
    };
    let result = fetch_observations(&endpoint, &codes(), &options);
    assert!(matches!(result, Err(FhirError::Http(m)) if m.contains("another origin")));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn plain_http_to_a_remote_host_is_refused() {
    let result = fetch_observations(
        "http://emr.hospital.example/fhir",
        &codes(),
        &ClientOptions::default(),
    );
    assert!(matches!(result, Err(FhirError::Http(m)) if m.contains("https")));
    assert!(fetch_observations("ftp://x/y", &codes(), &ClientOptions::default()).is_err());
    assert!(fetch_observations(
        "https://user:pw@evil.example/",
        &codes(),
        &ClientOptions::default()
    )
    .is_err());
}

#[test]
fn server_errors_are_reported() {
    let (endpoint, _) = serve(vec![(500, "nope".to_string())]);
    assert!(matches!(
        fetch_observations(&endpoint, &codes(), &ClientOptions::default()),
        Err(FhirError::Http(_))
    ));
}

#[test]
fn the_search_url_has_the_shape_servers_expect() {
    let url = search_url(
        "https://emr.example/fhir/R4/",
        &["8480-6".into(), "4548-4".into()],
        50,
    );
    assert_eq!(
        url,
        "https://emr.example/fhir/R4/Observation?code=http%3A%2F%2Floinc.org%7C8480-6,http%3A%2F%2Floinc.org%7C4548-4&_include=Observation:subject&_count=50"
    );
}
