//! A message the house sends itself — the family's sealed kit — written into one of its
//! own accounts and submitted over JMAP, as the administrator acting in that account.
//!
//! No password of the sending account is needed or kept: the administrator reaches
//! every account's `Email` and `EmailSubmission`, as it reaches a Sieve script.

use crate::{bounded, describe_set_error, Error, Result, Stalwart, MAX_BODY, MAX_ERROR};

const MAIL: &str = "urn:ietf:params:jmap:mail";
const SUBMISSION: &str = "urn:ietf:params:jmap:submission";

/// A file carried by a message.
pub struct Attachment<'a> {
    pub name: &'a str,
    pub mime: &'a str,
    pub bytes: &'a [u8],
}

/// One message to one recipient.
pub struct Outgoing<'a> {
    /// An address of an account Stalwart holds, which sends it.
    pub from: &'a str,
    pub from_name: &'a str,
    /// Where an answer goes — the sending account may be read by nobody.
    pub reply_to: Option<&'a str>,
    pub to: &'a str,
    pub subject: &'a str,
    pub text: &'a str,
    pub attachment: Option<Attachment<'a>>,
}

impl Stalwart {
    /// Submits `m`, leaving no copy in the sending account: the message is destroyed
    /// once submitted, so a kit sent never waits in a Sent folder for whoever opens it.
    /// Returns the submission's id. Submitted is not delivered — the queue says the rest.
    pub async fn send(&self, m: &Outgoing<'_>) -> Result<String> {
        let account = self
            .account_of(m.from)
            .await?
            .ok_or_else(|| Error::Unexpected(format!("no account {} to send from", m.from)))?;
        let identity = self.identity_of(&account, m.from).await?;
        let mailbox = self.drafts_of(&account).await?;

        let mut parts = vec![serde_json::json!({ "partId": "text", "type": "text/plain" })];
        if let Some(a) = &m.attachment {
            let blob = self.upload_bytes(&account, a.mime, a.bytes).await?;
            parts.push(serde_json::json!({
                "blobId": blob,
                "type": a.mime,
                "name": a.name,
                "disposition": "attachment",
            }));
        }
        let mut email = serde_json::json!({
            "mailboxIds": { mailbox: true },
            "keywords": { "$draft": true, "$seen": true },
            "from": [{ "name": m.from_name, "email": m.from }],
            "to": [{ "email": m.to }],
            "subject": m.subject,
            "bodyStructure": { "type": "multipart/mixed", "subParts": parts },
            "bodyValues": { "text": { "value": m.text } },
        });
        if let Some(r) = m.reply_to {
            email["replyTo"] = serde_json::json!([{ "email": r }]);
        }
        let answers = self
            .call_many(
                &[MAIL, SUBMISSION],
                vec![
                    serde_json::json!(["Email/set", { "accountId": account, "create": { "m": email } }, "0"]),
                    serde_json::json!(["EmailSubmission/set", {
                        "accountId": account,
                        "create": { "s": { "identityId": identity, "emailId": "#m" } },
                        "onSuccessDestroyEmail": ["#s"],
                    }, "1"]),
                ],
            )
            .await?;

        // 🔴 Each `/set` answers 200 with its refusal inside: read both.
        let created = |args: &serde_json::Value, key: &str, what: &str| -> Result<String> {
            if let Some(err) = args.get("notCreated").and_then(|v| v.get(key)) {
                return Err(Error::NotCreated {
                    object: format!("{what} to {}", m.to),
                    reason: describe_set_error(err),
                });
            }
            args.get("created")
                .and_then(|v| v.get(key))
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| Error::Unexpected(format!("{what} returned no id: {args}")))
        };
        let answer = |method: &str| {
            answers
                .iter()
                .find(|(name, _)| name == method)
                .map(|(_, args)| args)
                .ok_or_else(|| Error::Unexpected(format!("no answer to {method}")))
        };
        created(answer("Email/set")?, "m", "the message")?;
        let submission = created(answer("EmailSubmission/set")?, "s", "the submission")?;
        // The destruction answers as a second `Email/set`; a copy left behind is said.
        if let Some((_, args)) = answers.iter().rev().find(|(n, _)| n == "Email/set") {
            if args.get("notDestroyed").is_some_and(|v| !v.is_null()) {
                tracing::warn!(
                    from = m.from,
                    "a sent message's copy was left in its drafts"
                );
            }
        }
        Ok(submission)
    }

    /// Makes the account `address` hand whatever reaches it to `to`, keeping nothing.
    ///
    /// The envelope's sender must be the identity's own address (1.0.0 refuses any
    /// other, `forbiddenFrom`), so a relative's server refusing the kit answers
    /// `noreply@` — read by nobody, and a relative left without the kit went unsaid
    /// (lab, 2026-11-01). Its whole script is replaced, unlike a person's: its password
    /// is drawn and forgotten, so no rule in it was ever written by hand.
    pub async fn forward_everything(&self, address: &str, to: &str) -> Result<()> {
        let to = to.replace('\\', "\\\\").replace('"', "\\\"");
        // A redirect cancels the implicit keep: nothing waits in the account after.
        let script = format!("redirect \"{to}\";\n");
        self.apply_sieve(address, &|_| script.clone())
            .await
            .map(|_| ())
    }

    /// The identity of `account` that sends as `address`.
    async fn identity_of(&self, account: &str, address: &str) -> Result<String> {
        let answers = self
            .call_many(
                &[MAIL, SUBMISSION],
                vec![serde_json::json!(["Identity/get", { "accountId": account }, "0"])],
            )
            .await?;
        answers
            .first()
            .and_then(|(_, a)| a.get("list"))
            .and_then(|l| l.as_array())
            .and_then(|l| {
                l.iter().find(|i| {
                    i.get("email")
                        .and_then(|e| e.as_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case(address))
                })
            })
            .and_then(|i| i.get("id"))
            .and_then(|i| i.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("{address} has no identity to send as")))
    }

    /// The mailbox a message is written into before it is submitted.
    async fn drafts_of(&self, account: &str) -> Result<String> {
        let answers = self
            .call_many(
                &[MAIL],
                vec![serde_json::json!(["Mailbox/get", {
                    "accountId": account, "properties": ["role"]
                }, "0"])],
            )
            .await?;
        let list = answers
            .first()
            .and_then(|(_, a)| a.get("list"))
            .and_then(|l| l.as_array())
            .cloned()
            .unwrap_or_default();
        let id = |b: &serde_json::Value| b.get("id").and_then(|i| i.as_str()).map(str::to_string);
        list.iter()
            .find(|b| b.get("role").and_then(|r| r.as_str()) == Some("drafts"))
            .and_then(id)
            // An account without a drafts folder still has some mailbox to write into.
            .or_else(|| list.first().and_then(id))
            .ok_or_else(|| Error::Unexpected(format!("account {account} has no mailbox")))
    }

    /// Uploads `bytes` into `account`'s blobs.
    async fn upload_bytes(&self, account: &str, mime: &str, bytes: &[u8]) -> Result<String> {
        let url = format!("{}/jmap/upload/{account}/", self.base_url);
        let req = self.authed(
            self.http
                .post(&url)
                .header("Content-Type", mime)
                .body(bytes.to_vec()),
        );
        let resp = req.send().await.map_err(|source| Error::Http {
            source,
            context: "an attachment's upload".into(),
        })?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail =
                String::from_utf8_lossy(&bounded(resp, MAX_ERROR).await.unwrap_or_default())
                    .into_owned();
            return Err(Error::Api { status, detail });
        }
        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable upload response: {e}")))?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::Unexpected(format!("unreadable upload response: {e}")))?;
        v.get("blobId")
            .and_then(|b| b.as_str())
            .map(str::to_string)
            .ok_or_else(|| Error::Unexpected(format!("no blobId in the response: {v}")))
    }

    /// Several method calls in one request, every answer as `(method, arguments)`.
    /// A method's `error` answer fails the whole call.
    async fn call_many(
        &self,
        extra: &[&'static str],
        calls: Vec<serde_json::Value>,
    ) -> Result<Vec<(String, serde_json::Value)>> {
        let mut using = vec![crate::CORE];
        using.extend_from_slice(extra);
        let body = serde_json::json!({ "using": using, "methodCalls": calls });
        let resp = self
            .authed(self.http.post(self.endpoint()).json(&body))
            .send()
            .await
            .map_err(|source| Error::Http {
                source,
                context: "a message's submission".into(),
            })?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::Unauthorized);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let detail =
                String::from_utf8_lossy(&bounded(resp, MAX_ERROR).await.unwrap_or_default())
                    .into_owned();
            return Err(Error::Api { status, detail });
        }
        let body = bounded(resp, MAX_BODY)
            .await
            .map_err(|e| Error::Unexpected(format!("unreadable response: {e}")))?;
        let v: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::Unexpected(format!("unreadable response: {e}")))?;
        answers(&v)
    }
}

/// A JMAP response's answers; the first `error` among them fails it.
fn answers(v: &serde_json::Value) -> Result<Vec<(String, serde_json::Value)>> {
    let mut out = Vec::new();
    for r in v
        .get("methodResponses")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
    {
        let name = r.get(0).and_then(|n| n.as_str()).unwrap_or("?").to_string();
        let args = r.get(1).cloned().unwrap_or_default();
        if name == "error" {
            let t = args
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            return Err(Error::Api {
                status: 200,
                detail: format!("JMAP error \"{t}\": {args}"),
            });
        }
        out.push((name, args));
    }
    if out.is_empty() {
        return Err(Error::Unexpected("no method response".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_error_fails_the_whole_request() {
        // A submission refused comes back as an `error` answer under HTTP 200: read as
        // an answer like the others, the message would be reported sent.
        let v = serde_json::json!({ "methodResponses": [
            ["Email/set", { "created": { "m": { "id": "e1" } } }, "0"],
            ["error", { "type": "forbiddenFrom" }, "1"],
        ]});
        let e = answers(&v).expect_err("refused");
        assert!(e.to_string().contains("forbiddenFrom"), "{e}");
        assert!(answers(&serde_json::json!({})).is_err());
    }
}
