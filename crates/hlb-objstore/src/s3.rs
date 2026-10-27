//! Just enough S3 to prove a backup destination cannot be erased — and to read a
//! bucket out, object by object, and write it back.
//!
//! restic only says whether a deletion was refused, and on a versioned bucket a
//! deletion is never refused: it hides the object behind a marker and keeps it. What
//! decides is whether the credential can delete a VERSION — so the proof writes a
//! witness, tries to delete the very version it wrote, and reads it back. Four calls,
//! signed by hand (AWS Signature Version 4) rather than through an SDK of several
//! hundred crates.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// A restic `s3:` location, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// `https://host[:port]`.
    pub endpoint: String,
    pub bucket: String,
    /// Where the repository sits inside the bucket, without slashes around it.
    pub prefix: String,
}

impl Location {
    /// `s3:https://host/bucket/prefix`, or `s3:host/bucket` — HTTPS when no scheme
    /// is written, as restic reads it.
    pub fn parse(location: &str) -> Option<Self> {
        let rest = location.trim().strip_prefix("s3:")?;
        let (scheme, rest) = match rest.split_once("://") {
            Some((s, r)) if s == "http" || s == "https" => (s, r),
            Some(_) => return None,
            None => ("https", rest),
        };
        // Credentials written into the URL are not the endpoint.
        let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
        let mut parts = rest.trim_end_matches('/').splitn(3, '/');
        let host = parts.next().filter(|h| !h.is_empty())?;
        let bucket = parts.next().filter(|b| !b.is_empty())?;
        Some(Self {
            endpoint: format!("{scheme}://{host}"),
            bucket: bucket.to_string(),
            prefix: parts.next().unwrap_or("").trim_matches('/').to_string(),
        })
    }

    /// `name` inside the repository's prefix.
    pub fn key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}/{name}", self.prefix)
        }
    }

    fn host(&self) -> &str {
        self.endpoint
            .split_once("://")
            .map_or(self.endpoint.as_str(), |(_, h)| h)
    }
}

/// What a request got back.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub version_id: Option<String>,
    pub body: String,
}

/// A bucket, reached with one credential.
pub struct Bucket {
    location: Location,
    region: String,
    access_key: String,
    secret_key: String,
    http: reqwest::Client,
}

/// The one lifecycle rule Homelabus writes, by its id.
const LIFECYCLE_RULE: &str = "homelabus-expiry";

/// The region a request is signed for before the bucket has said its own.
const FIRST_REGION: &str = "us-east-1";

impl Bucket {
    /// Asks the bucket its region — signed for `us-east-1`, which every S3 accepts for
    /// this one call — so that the requests after it are signed for the right one.
    pub async fn connect(location: Location, access_key: &str, secret_key: &str) -> Result<Self> {
        let mut b = Self {
            location,
            region: FIRST_REGION.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
            // No total timeout: an object of a gigabyte streams for longer than any. A
            // server that stops answering is caught by the read timeout instead.
            http: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(30))
                .read_timeout(std::time::Duration::from_secs(300))
                .build()
                .map_err(|e| Error::Unreachable(e.to_string()))?,
        };
        let r = b.send("GET", None, &[("location", "")], Vec::new()).await?;
        if let Some(region) = between(&r.body, "<LocationConstraint>", "</LocationConstraint>")
            .filter(|r| !r.is_empty())
        {
            b.region = region.to_string();
        } else if let Some(region) = between(&r.body, "<Region>", "</Region>") {
            // Refused for the wrong region, the answer names the right one.
            b.region = region.to_string();
        }
        Ok(b)
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    /// The bucket's versioning: `Enabled`, `Suspended`, or `None` when it never had
    /// any — or the store does not know what it is (Garage answers that way).
    pub async fn versioning(&self) -> Result<(u16, Option<String>)> {
        let r = self
            .send("GET", None, &[("versioning", "")], Vec::new())
            .await?;
        Ok((
            r.status,
            between(&r.body, "<Status>", "</Status>").map(str::to_string),
        ))
    }

    /// Has the store delete every object older than `days`, and abandon an upload left
    /// unfinished as long — then reads the rule back, since a store that ignored part of
    /// it would answer 200 all the same. The bucket's whole lifecycle is this one rule.
    ///
    /// ⚠️ Garage 2.4.1 takes it from a key with read and write and no ownership
    /// (measured): `owner: false` does not keep an app from expiring its own bucket —
    /// nothing more than deleting each object, which writing already allows.
    pub async fn expire_after(&self, days: u32) -> Result<()> {
        let rule = format!(
            "<LifecycleConfiguration><Rule><ID>{LIFECYCLE_RULE}</ID><Status>Enabled</Status>\
             <Filter></Filter><Expiration><Days>{days}</Days></Expiration>\
             <AbortIncompleteMultipartUpload><DaysAfterInitiation>{days}\
             </DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>\
             </LifecycleConfiguration>"
        );
        let put = self
            .send("PUT", None, &[("lifecycle", "")], rule.into_bytes())
            .await?;
        if !(200..300).contains(&put.status) {
            return Err(Error::Rejected {
                operation: "PutBucketLifecycleConfiguration",
                status: put.status,
                body: put.body.chars().take(300).collect(),
            });
        }
        let back = self
            .send("GET", None, &[("lifecycle", "")], Vec::new())
            .await?;
        let held = between(&back.body, "<Expiration><Days>", "</Days>")
            == Some(days.to_string().as_str())
            && between(
                &back.body,
                "<DaysAfterInitiation>",
                "</DaysAfterInitiation>",
            ) == Some(days.to_string().as_str());
        if !held {
            return Err(Error::Malformed {
                operation: "GetBucketLifecycleConfiguration",
                reason: format!(
                    "the rule written does not read back: {}",
                    back.body.chars().take(300).collect::<String>()
                ),
            });
        }
        Ok(())
    }

    pub async fn put(&self, key: &str, body: &[u8]) -> Result<Reply> {
        self.send("PUT", Some(key), &[], body.to_vec()).await
    }

    pub async fn get(&self, key: &str, version: Option<&str>) -> Result<Reply> {
        let q: Vec<(&str, &str)> = version.map(|v| ("versionId", v)).into_iter().collect();
        self.send("GET", Some(key), &q, Vec::new()).await
    }

    pub async fn delete(&self, key: &str, version: Option<&str>) -> Result<Reply> {
        let q: Vec<(&str, &str)> = version.map(|v| ("versionId", v)).into_iter().collect();
        self.send("DELETE", Some(key), &q, Vec::new()).await
    }

    /// Every object, by key — in the order the store lists them, which S3 makes the
    /// keys' byte order: an archive written in it deduplicates against the last one.
    pub async fn list(&self) -> Result<Vec<Object>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut q: Vec<(&str, &str)> = vec![("list-type", "2")];
            if let Some(t) = &token {
                q.push(("continuation-token", t));
            }
            let r = self.send("GET", None, &q, Vec::new()).await?;
            if r.status != 200 {
                return Err(Error::Rejected {
                    operation: "ListObjectsV2",
                    status: r.status,
                    body: r.body.chars().take(300).collect(),
                });
            }
            let mut rest = r.body.as_str();
            while let Some(c) = between(rest, "<Contents>", "</Contents>") {
                let key = between(c, "<Key>", "</Key>").map(unescape).ok_or_else(|| {
                    Error::Malformed {
                        operation: "ListObjectsV2",
                        reason: "an object without a key".into(),
                    }
                })?;
                let size = between(c, "<Size>", "</Size>")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let modified = between(c, "<LastModified>", "</LastModified>")
                    .and_then(epoch_of)
                    .unwrap_or(0);
                out.push(Object {
                    key,
                    size,
                    modified,
                });
                rest = &rest[rest.find("</Contents>").map_or(rest.len(), |p| p + 11)..];
            }
            // A cut list is an error, never a short one: a bucket backed up from its
            // first thousand objects restores the first thousand.
            if between(&r.body, "<IsTruncated>", "</IsTruncated>") != Some("true") {
                return Ok(out);
            }
            token = Some(
                between(
                    &r.body,
                    "<NextContinuationToken>",
                    "</NextContinuationToken>",
                )
                .map(unescape)
                .ok_or_else(|| Error::Malformed {
                    operation: "ListObjectsV2",
                    reason: "truncated, and no token to read on".into(),
                })?,
            );
        }
    }

    /// An object, its content to be read through [`Download::chunk`].
    pub async fn open(&self, key: &str) -> Result<Download> {
        let r = self
            .request(
                "GET",
                Some(key),
                &[],
                &[],
                reqwest::Body::from(Vec::new()),
                &hex(&Sha256::digest([])),
            )
            .await?;
        let status = r.status().as_u16();
        if status != 200 {
            let body = r.text().await.unwrap_or_default();
            return Err(Error::Rejected {
                operation: "GetObject",
                status,
                body: body.chars().take(300).collect(),
            });
        }
        let headers = KEPT
            .iter()
            .filter_map(|h| {
                r.headers()
                    .get(*h)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| (h.to_string(), v.to_string()))
            })
            .chain(r.headers().iter().filter_map(|(k, v)| {
                k.as_str()
                    .starts_with("x-amz-meta-")
                    .then(|| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
                    .flatten()
            }))
            .collect();
        let size = r.content_length().ok_or_else(|| Error::Malformed {
            operation: "GetObject",
            reason: format!("{key}: no length"),
        })?;
        Ok(Download {
            size,
            headers,
            response: r,
        })
    }

    /// Writes `key` from `body`, `size` bytes long, with the headers it had. Signed as
    /// `UNSIGNED-PAYLOAD`: hashing first would read the object twice.
    pub async fn put_stream(
        &self,
        key: &str,
        size: u64,
        headers: &[(String, String)],
        body: reqwest::Body,
    ) -> Result<()> {
        let mut sent: Vec<(String, String)> = vec![("content-length".into(), size.to_string())];
        sent.extend(
            headers
                .iter()
                .filter(|(k, _)| KEPT.contains(&k.as_str()) || k.starts_with("x-amz-meta-"))
                .cloned(),
        );
        let r = self
            .request("PUT", Some(key), &[], &sent, body, "UNSIGNED-PAYLOAD")
            .await?;
        let status = r.status().as_u16();
        if !(200..300).contains(&status) {
            let body = r.text().await.unwrap_or_default();
            return Err(Error::Rejected {
                operation: "PutObject",
                status,
                body: body.chars().take(300).collect(),
            });
        }
        Ok(())
    }

    /// Path-style: `endpoint/bucket/key`. Every S3 this targets accepts it; a
    /// bucket's own host name would need DNS a self-hosted store may not have.
    async fn send(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<Reply> {
        let payload = hex(&Sha256::digest(&body));
        let r = self
            .request(method, key, query, &[], reqwest::Body::from(body), &payload)
            .await?;
        let status = r.status().as_u16();
        let version_id = r
            .headers()
            .get("x-amz-version-id")
            .and_then(|v| v.to_str().ok())
            // `null` is the version of an object written while versioning was off.
            .filter(|v| !v.is_empty() && *v != "null")
            .map(str::to_string);
        let body = r.text().await.unwrap_or_default();
        Ok(Reply {
            status,
            version_id,
            body,
        })
    }

    /// One signed request: every header sent is signed, `x-amz-meta-*` included, which
    /// S3 requires of them.
    async fn request(
        &self,
        method: &str,
        key: Option<&str>,
        query: &[(&str, &str)],
        extra: &[(String, String)],
        body: reqwest::Body,
        payload: &str,
    ) -> Result<reqwest::Response> {
        let uri = match key {
            Some(k) => format!("/{}/{}", self.location.bucket, k),
            None => format!("/{}/", self.location.bucket),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_default();
        let date = amz_date(now);
        let host = self.location.host().to_string();
        let mut headers: Vec<(&str, &str)> = vec![
            ("host", host.as_str()),
            ("x-amz-content-sha256", payload),
            ("x-amz-date", date.as_str()),
        ];
        headers.extend(extra.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        let authorization = sign(
            &Request {
                method,
                uri: &uri,
                query,
                headers: &headers,
                payload,
            },
            &date,
            &self.region,
            &self.access_key,
            &self.secret_key,
        );
        let url = format!(
            "{}{}{}",
            self.location.endpoint,
            encode_path(&uri),
            if query.is_empty() {
                String::new()
            } else {
                format!("?{}", canonical_query(query))
            }
        );
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| Error::Unreachable(e.to_string()))?;
        let mut req = self
            .http
            .request(method, &url)
            .header("authorization", authorization);
        for (k, v) in headers.iter().filter(|(k, _)| *k != "host") {
            req = req.header(*k, *v);
        }
        req.body(body)
            .send()
            .await
            .map_err(|e| Error::Unreachable(format!("{}: {e}", self.location.endpoint)))
    }
}

/// An object, as a bucket lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub key: String,
    pub size: u64,
    /// Seconds since the epoch.
    pub modified: i64,
}

/// The headers an object keeps through a backup: what an app set when it wrote it, and
/// reads back — a picture served without its `content-type` is a download.
pub const KEPT: &[&str] = &[
    "content-type",
    "content-disposition",
    "content-encoding",
    "content-language",
    "cache-control",
    "expires",
];

/// An object being read.
pub struct Download {
    pub size: u64,
    /// [`KEPT`] and every `x-amz-meta-*` it carries.
    pub headers: Vec<(String, String)>,
    response: reqwest::Response,
}

impl Download {
    /// The next part of its content; `None` once it is all read.
    pub async fn chunk(&mut self) -> Result<Option<Vec<u8>>> {
        self.response
            .chunk()
            .await
            .map(|c| c.map(|b| b.to_vec()))
            .map_err(|e| Error::Unreachable(format!("reading an object: {e}")))
    }
}

/// XML's five entities and numeric references, as S3 escapes a key.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let name = &tail[1..end];
        let c = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            n if n.starts_with("#x") => u32::from_str_radix(&n[2..], 16)
                .ok()
                .and_then(char::from_u32),
            n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match c {
            Some(c) => out.push(c),
            None => out.push_str(&tail[..=end]),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `2026-10-26T19:43:26.000Z` in seconds since the epoch.
fn epoch_of(s: &str) -> Option<i64> {
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, m, d) = (n(0, 4)?, n(5, 7)?, n(8, 10)?);
    let (hh, mm, ss) = (n(11, 13)?, n(14, 16)?, n(17, 19)?);
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// A request as Signature Version 4 sees it.
struct Request<'a> {
    method: &'a str,
    /// Not yet encoded.
    uri: &'a str,
    query: &'a [(&'a str, &'a str)],
    /// Lower-case names; every one is signed.
    headers: &'a [(&'a str, &'a str)],
    /// The body's SHA-256, in hexadecimal.
    payload: &'a str,
}

/// The `Authorization` header for `r`, sent at `date` (`20130524T000000Z`).
fn sign(r: &Request<'_>, date: &str, region: &str, access_key: &str, secret_key: &str) -> String {
    let mut headers: Vec<(&str, &str)> = r.headers.to_vec();
    headers.sort();
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
    let signed = signed.join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
        r.method,
        encode_path(r.uri),
        canonical_query(r.query),
        r.payload
    );
    let day = &date[..8.min(date.len())];
    let scope = format!("{day}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let mut key = hmac(format!("AWS4{secret_key}").as_bytes(), day.as_bytes());
    for part in [region, "s3", "aws4_request"] {
        key = hmac(&key, part.as_bytes());
    }
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={}",
        hex(&hmac(&key, to_sign.as_bytes()))
    )
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // Any key length is accepted: `new_from_slice` fails on none of them for HMAC.
    match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mut m) => {
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        Err(_) => Vec::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every byte but the unreserved ones, percent-encoded — `/` kept in a path.
fn encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn encode_path(p: &str) -> String {
    encode(p, true)
}

fn canonical_query(q: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = q
        .iter()
        .map(|(k, v)| (encode(k, false), encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// `20130524T000000Z`, from seconds since the epoch.
fn amz_date(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let secs = epoch.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let end = s[start..].find(close)? + start;
    Some(&s[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_key_and_date_read_as_the_store_meant_them() {
        assert_eq!(
            unescape("a &amp; b &lt;c&gt; &#233;t&#xE9; &quot;&apos;"),
            "a & b <c> été \"'"
        );
        assert_eq!(unescape("no entity; &unknown; &"), "no entity; &unknown; &");
        assert_eq!(epoch_of("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(epoch_of("2026-10-26T19:43:26.000Z"), Some(1_793_043_806));
        assert_eq!(amz_date(1_793_043_806), "20261026T194326Z");
        assert_eq!(epoch_of("garbage"), None);
    }

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn signature(
        uri: &str,
        query: &[(&str, &str)],
        extra: &[(&str, &str)],
        payload: &str,
    ) -> String {
        let mut headers = vec![
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", payload),
            ("x-amz-date", "20130524T000000Z"),
        ];
        headers.extend(extra);
        let auth = sign(
            &Request {
                method: "GET",
                uri,
                query,
                headers: &headers,
                payload,
            },
            "20130524T000000Z",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        auth.rsplit_once("Signature=")
            .map(|(_, s)| s.to_string())
            .unwrap_or_default()
    }

    /// The examples of AWS's own documentation of Signature Version 4 for S3.
    #[test]
    fn the_signature_is_the_one_aws_documents() {
        assert_eq!(
            signature("/test.txt", &[], &[("range", "bytes=0-9")], EMPTY),
            "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            signature("/", &[("lifecycle", "")], &[], EMPTY),
            "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        );
        assert_eq!(
            signature("/", &[("max-keys", "2"), ("prefix", "J")], &[], EMPTY),
            "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
        );
    }

    #[test]
    fn a_restic_location_is_taken_apart_as_restic_reads_it() {
        let l = Location::parse("s3:https://s3.fr-par.scw.cloud/homelab/restic/").expect("s3");
        assert_eq!(l.endpoint, "https://s3.fr-par.scw.cloud");
        assert_eq!(
            (l.bucket.as_str(), l.prefix.as_str()),
            ("homelab", "restic")
        );
        assert_eq!(l.key("hlb-witness/1"), "restic/hlb-witness/1");
        let l = Location::parse("s3:http://garage:3900/hlb-backups").expect("garage");
        assert_eq!(
            (l.endpoint.as_str(), l.bucket.as_str(), l.key("w")),
            ("http://garage:3900", "hlb-backups", "w".to_string())
        );
        assert_eq!(
            Location::parse("s3:s3.amazonaws.com/b").map(|l| l.endpoint),
            Some("https://s3.amazonaws.com".to_string())
        );
        let l = Location::parse("s3:https://key:secret@host/b").expect("credentials");
        assert_eq!(l.endpoint, "https://host");
        assert!(Location::parse("rest:http://nas:8000/").is_none());
        assert!(Location::parse("s3:https://host").is_none());
    }

    #[test]
    fn the_date_is_written_as_aws_reads_it() {
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(amz_date(951_782_400 + 3661), "20000229T010101Z");
    }
}
