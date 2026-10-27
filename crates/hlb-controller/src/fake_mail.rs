//! A Stalwart that keeps its accounts in memory, for the routes that create mail.
//!
//! Only the JMAP the account and alias calls speak: domains, accounts, their aliases.
//! It answers like 0.16 — a list is a map keyed by index — so a client that reads an
//! array would find nothing here either.

// Gated here as well as in `lib.rs`: the source scans read every file, and cut each
// at its tests.
#[cfg(test)]
pub(crate) mod stalwart {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::routing::post;
    use serde_json::{json, Value};

    /// What the fake holds: `local → aliases`, one domain.
    #[derive(Default)]
    pub struct Mailboxes {
        pub accounts: BTreeMap<String, Vec<String>>,
    }

    pub struct FakeStalwart {
        pub held: Arc<Mutex<Mailboxes>>,
        pub client: Arc<hlb_mail::Stalwart>,
    }

    /// A fake Stalwart listening on a free local port, holding `accounts` already.
    pub async fn start(accounts: &[&str]) -> FakeStalwart {
        let held = Arc::new(Mutex::new(Mailboxes {
            accounts: accounts
                .iter()
                .map(|a| (a.to_string(), Vec::new()))
                .collect(),
        }));
        let h = held.clone();
        let app = axum::Router::new().route(
            "/jmap/",
            post(move |axum::Json(body): axum::Json<Value>| {
                let h = h.clone();
                async move { axum::Json(answer(&h, &body)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        FakeStalwart {
            held,
            client: Arc::new(hlb_mail::Stalwart::new(
                format!("http://{addr}"),
                hlb_mail::Auth::Bearer("t".into()),
            )),
        }
    }

    /// The value of `key` anywhere in `v` — a filter nests its conditions.
    fn find<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
        match v {
            Value::Object(m) => m.get(key).or_else(|| m.values().find_map(|x| find(x, key))),
            Value::Array(a) => a.iter().find_map(|x| find(x, key)),
            _ => None,
        }
    }

    fn answer(held: &Mutex<Mailboxes>, body: &Value) -> Value {
        let call = &body["methodCalls"][0];
        let (method, args) = (call[0].as_str().unwrap_or(""), &call[1]);
        let mut h = held.lock().expect("fake mail");
        let result = match method {
            "x:Domain/query" => json!({ "ids": ["d1"] }),
            "x:Domain/set" => json!({ "created": { "new": { "id": "d1" } } }),
            "x:Account/query" => {
                let name = find(&args["filter"], "name").and_then(Value::as_str);
                let ids: Vec<&String> = h
                    .accounts
                    .keys()
                    .filter(|k| Some(k.as_str()) == name)
                    .collect();
                json!({ "ids": ids })
            }
            "x:Account/get" => {
                let list: Vec<Value> = args["ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter_map(|id| h.accounts.get(id).map(|a| (id, a)))
                    .map(|(id, aliases)| {
                        let map: serde_json::Map<String, Value> = aliases
                            .iter()
                            .enumerate()
                            .map(|(i, a)| (i.to_string(), json!({ "name": a, "domainId": "d1" })))
                            .collect();
                        json!({ "id": id, "aliases": map })
                    })
                    .collect();
                json!({ "list": list })
            }
            "x:Account/set" => {
                if let Some(name) = args["create"]["new"]["name"].as_str() {
                    h.accounts.insert(name.to_string(), Vec::new());
                    json!({ "created": { "new": { "id": name } } })
                } else if let Some(update) = args["update"].as_object() {
                    for (id, patch) in update {
                        let aliases = patch["aliases"]
                            .as_object()
                            .map(|m| {
                                m.values()
                                    .filter_map(|a| a["name"].as_str().map(str::to_string))
                                    .collect()
                            })
                            .unwrap_or_default();
                        h.accounts.insert(id.clone(), aliases);
                    }
                    json!({ "updated": {} })
                } else {
                    json!({})
                }
            }
            _ => json!({}),
        };
        json!({ "methodResponses": [[method, result, "c0"]] })
    }
}
