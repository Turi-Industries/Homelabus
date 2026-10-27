//! What the internet resolves, asked of a public resolver over HTTPS.
//!
//! 🔴 Never the house's own resolver: a split-horizon zone answers inside for names a
//! receiver outside never sees, and a mail record judged present there is missing for
//! Gmail. DNS over HTTPS needs nothing beyond the HTTP client already here, and reaches
//! out where port 53 to the internet is filtered.

use std::time::Duration;

/// The resolvers asked, in order: the next is asked only when one cannot answer.
pub const RESOLVERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

pub struct PublicDns {
    http: reqwest::Client,
    resolvers: Vec<String>,
}

impl Default for PublicDns {
    fn default() -> Self {
        Self::new(RESOLVERS.iter().map(|s| s.to_string()).collect())
    }
}

impl PublicDns {
    pub fn new(resolvers: Vec<String>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            resolvers,
        }
    }

    /// The data of every `kind` record at `name`, as the resolver wrote it — a TXT
    /// quoted or not, depending on which answered. `Ok(empty)` when the name holds
    /// none; `Err` when no resolver could say.
    pub async fn lookup(&self, name: &str, kind: &str) -> Result<Vec<String>, String> {
        let mut why = Vec::new();
        for r in &self.resolvers {
            match self.ask(r, name, kind).await {
                Ok(found) => return Ok(found),
                Err(e) => why.push(format!("{r}: {e}")),
            }
        }
        Err(why.join("; "))
    }

    async fn ask(&self, resolver: &str, name: &str, kind: &str) -> Result<Vec<String>, String> {
        let resp = self
            .http
            .get(resolver)
            .query(&[("name", name), ("type", kind)])
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;
        // A DNS answer is a few kilobytes; one a megabyte long is not one.
        let body = crate::bounded(resp, 1024 * 1024).await?;
        let body: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        answers(&body, kind)
    }
}

/// The data of a JSON answer's records of `kind`. NXDOMAIN is no record, which is an
/// answer; SERVFAIL and the rest are not.
pub fn answers(body: &serde_json::Value, kind: &str) -> Result<Vec<String>, String> {
    const NOERROR: u64 = 0;
    const NXDOMAIN: u64 = 3;
    let code = match kind {
        "TXT" => 16,
        "MX" => 15,
        other => return Err(format!("{other} is not a type read here")),
    };
    match body.get("Status").and_then(serde_json::Value::as_u64) {
        Some(NOERROR) => {}
        Some(NXDOMAIN) => return Ok(Vec::new()),
        Some(status) => return Err(format!("the resolver answered DNS status {status}")),
        None => return Err("the resolver's answer has no status".into()),
    }
    // A CNAME on the way is in the answer too: only the records asked for count.
    Ok(body
        .get("Answer")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("type").and_then(serde_json::Value::as_u64) == Some(code))
        .filter_map(|a| a.get("data").and_then(|d| d.as_str()).map(str::to_string))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_of_the_type_asked_are_read_and_a_cname_on_the_way_is_not() {
        let body = serde_json::json!({
            "Status": 0,
            "Answer": [
                { "name": "x.example.org", "type": 5, "data": "y.example.org." },
                { "name": "y.example.org", "type": 16, "data": "\"v=spf1 mx -all\"" },
            ],
        });
        assert_eq!(answers(&body, "TXT").expect("read"), ["\"v=spf1 mx -all\""]);
    }

    #[test]
    fn a_name_that_does_not_exist_holds_nothing_and_a_failure_is_no_answer() {
        assert!(answers(&serde_json::json!({ "Status": 3 }), "MX")
            .expect("an answer")
            .is_empty());
        assert!(answers(&serde_json::json!({ "Status": 0 }), "MX")
            .expect("an answer")
            .is_empty());
        assert!(answers(&serde_json::json!({ "Status": 2 }), "MX").is_err());
    }
}
