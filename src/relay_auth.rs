use crate::relay::{ApiError, Relay, WebResult, escaped, hash, random, require, value_str};
use crate::store::now;
use axum::{
    Form, Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use subtle::ConstantTimeEq;

type Fields = HashMap<String, String>;
fn field<'a>(f: &'a Fields, key: &str) -> WebResult<&'a str> {
    f.get(key)
        .map(String::as_str)
        .ok_or(ApiError::bad("invalid_request"))
}
fn ct(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn page(title: &str, body: String) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><link rel=icon type=image/x-icon href=/favicon.ico><link rel=icon type=image/png sizes=32x32 href=/icon.png><title>ferroc — {}</title><body><h1>ferroc — {}</h1>{}</body></html>",
        escaped(title),
        escaped(title),
        body
    ))
}
fn cookie(h: &HeaderMap) -> Option<&str> {
    h.get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == "ferroc_session")
        .map(|(_, v)| v)
}
fn session(s: &Relay, h: &HeaderMap) -> WebResult<Value> {
    let raw = cookie(h)
        .filter(|x| x.len() <= 256)
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "login_required"))?;
    s.store
        .get("session", &hash(raw))?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "login_required"))
}
fn origin(s: &Relay, h: &HeaderMap) -> WebResult<()> {
    require(
        h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(s.origin.as_str()),
        "origin_mismatch",
    )
}
fn authenticated_form(s: &Relay, h: &HeaderMap, f: &Fields) -> WebResult<Value> {
    origin(s, h)?;
    let session = session(s, h)?;
    require(
        ct(field(f, "csrf")?, value_str(&session, "csrf")?),
        "csrf_mismatch",
    )?;
    Ok(session)
}
fn safe_return(input: &str) -> &str {
    if input.starts_with('/')
        && !input.starts_with("//")
        && !input.contains('\\')
        && !input.chars().any(char::is_control)
    {
        input
    } else {
        "/admin"
    }
}
fn login_redirect(s: &Relay, path: &str) -> Response {
    let mut u = reqwest::Url::parse(&format!("{}/auth/login", s.origin)).expect("origin");
    u.query_pairs_mut().append_pair("returnTo", path);
    Redirect::to(u.as_str()).into_response()
}
fn csrf(session: &Value) -> String {
    format!(
        "<input type=hidden name=csrf value=\"{}\">",
        escaped(session["csrf"].as_str().unwrap_or_default())
    )
}
fn validate_redirect(uri: &str) -> WebResult<()> {
    let u = crate::transport::relay_url(uri).map_err(|_| ApiError::bad("invalid_redirect_uri"))?;
    require(u.fragment().is_none(), "invalid_redirect_uri")
}

pub(crate) fn routes(r: Router<Arc<Relay>>) -> Router<Arc<Relay>> {
    r.route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/.well-known/oauth-protected-resource", get(resource))
        .route("/.well-known/oauth-protected-resource/mcp", get(resource))
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/auth/login", get(login_page).post(login))
        .route("/auth/consent", get(consent_page).post(consent))
        .route("/auth/logout", post(logout))
        .route("/device/verify", get(verify_page))
        .route("/device/approve", post(approve))
        .route("/", get(admin))
        .route("/admin", get(admin))
        .route("/admin/device", post(admin_device))
        .route("/auth/clients", get(clients))
        .route("/auth/clients/delete", post(delete_client))
}
async fn metadata(State(s): State<Arc<Relay>>) -> Json<Value> {
    Json(
        json!({"issuer":s.origin,"authorization_endpoint":format!("{}/authorize",s.origin),"token_endpoint":format!("{}/token",s.origin),"registration_endpoint":format!("{}/register",s.origin),"revocation_endpoint":format!("{}/revoke",s.origin),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"token_endpoint_auth_methods_supported":["none","client_secret_post"],"code_challenge_methods_supported":["S256"],"scopes_supported":["mcp:tools"],"authorization_response_iss_parameter_supported":true}),
    )
}
async fn resource(State(s): State<Arc<Relay>>) -> Json<Value> {
    Json(
        json!({"resource":format!("{}/mcp",s.origin),"authorization_servers":[s.origin],"scopes_supported":["mcp:tools"],"resource_name":"ferroc"}),
    )
}
async fn register(
    State(s): State<Arc<Relay>>,
    Json(v): Json<Value>,
) -> WebResult<(StatusCode, Json<Value>)> {
    let redirects = v["redirect_uris"]
        .as_array()
        .ok_or(ApiError::bad("invalid_redirect_uri"))?;
    require(
        !redirects.is_empty() && redirects.len() <= 8,
        "invalid_redirect_uri",
    )?;
    for uri in redirects {
        validate_redirect(uri.as_str().ok_or(ApiError::bad("invalid_redirect_uri"))?)?;
    }
    let method = v
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("none");
    require(
        ["none", "client_secret_post"].contains(&method),
        "invalid_client_metadata",
    )?;
    let name = v
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("MCP client");
    require(name.len() <= 80, "invalid_client_metadata")?;
    let id = format!("fc_{}", random());
    let secret = if method == "none" {
        None
    } else {
        Some(random())
    };
    let mut response = json!({"client_id":id,"client_id_issued_at":now(),"client_name":name,"redirect_uris":redirects,"token_endpoint_auth_method":method,"grant_types":["authorization_code","refresh_token"],"response_types":["code"]});
    let mut stored = response.clone();
    if let Some(secret) = secret {
        stored["secretHash"] = json!(hash(&secret));
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }
    s.store.put("client", &id, &stored, 365 * 86400)?;
    Ok((StatusCode::CREATED, Json(response)))
}
async fn login_page(Query(q): Query<Fields>) -> Html<String> {
    let target = safe_return(q.get("returnTo").map(String::as_str).unwrap_or("/admin"));
    page(
        "Login",
        format!(
            "<form method=post action=/auth/login><input type=hidden name=returnTo value=\"{}\"><label>User <input name=username value=admin autocomplete=username></label><label>Password <input name=password type=password autocomplete=current-password></label><button>Login</button></form>",
            escaped(target)
        ),
    )
}
async fn login(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    origin(&s, &h)?;
    let password = field(&f, "password")?;
    require(password.len() <= 1024, "invalid_request")?;
    let mut gate = s.login_gate.lock().await;
    if now() < gate.1 {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    let hashed = s.password_hash.clone();
    let supplied = password.to_owned();
    let ok = tokio::task::spawn_blocking(move || {
        use scrypt::{
            Scrypt,
            password_hash::{PasswordHash, PasswordVerifier},
        };
        PasswordHash::new(&hashed)
            .ok()
            .is_some_and(|p| Scrypt.verify_password(supplied.as_bytes(), &p).is_ok())
    })
    .await
    .map_err(anyhow::Error::from)?
        && f.get("username").is_some_and(|v| v == "admin");
    if !ok {
        gate.0 += 1;
        if gate.0 >= 5 {
            gate.1 = now() + 300;
        }
        return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid_credentials"));
    }
    *gate = (0, 0);
    drop(gate);
    let token = random();
    s.store.put(
        "session",
        &hash(&token),
        &json!({"csrf":random()}),
        8 * 3600,
    )?;
    let target = safe_return(f.get("returnTo").map(String::as_str).unwrap_or("/admin"));
    let mut r = Redirect::to(target).into_response();
    let secure = if s.origin.starts_with("https:") {
        "; Secure"
    } else {
        ""
    };
    r.headers_mut().insert(
        header::SET_COOKIE,
        format!("ferroc_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800{secure}")
            .parse()
            .map_err(anyhow::Error::from)?,
    );
    Ok(r)
}
async fn logout(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    authenticated_form(&s, &h, &f)?;
    if let Some(t) = cookie(&h) {
        s.store.delete("session", &hash(t))?;
    }
    let mut r = Redirect::to("/auth/login").into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        "ferroc_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
            .parse()
            .expect("cookie"),
    );
    Ok(r)
}
async fn authorize(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Query(q): Query<Fields>,
) -> WebResult<Response> {
    require(
        field(&q, "response_type")? == "code" && field(&q, "code_challenge_method")? == "S256",
        "invalid_request",
    )?;
    let client_id = field(&q, "client_id")?;
    let client = s
        .store
        .get("client", client_id)?
        .ok_or(ApiError::bad("invalid_client"))?;
    let redirect = field(&q, "redirect_uri")?;
    require(
        client["redirect_uris"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == redirect)),
        "invalid_redirect_uri",
    )?;
    let challenge = field(&q, "code_challenge")?;
    require(
        challenge.len() == 43
            && challenge
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "invalid_request",
    )?;
    require(
        q.get("scope").is_none_or(|v| v == "mcp:tools"),
        "invalid_scope",
    )?;
    let resource = format!("{}/mcp", s.origin);
    require(
        q.get("resource").is_none_or(|v| v == &resource),
        "invalid_target",
    )?;
    require(
        q.get("state").is_none_or(|v| v.len() <= 1024),
        "invalid_request",
    )?;
    let pending = random();
    s.store.put("pending",&pending,&json!({"client_id":client_id,"redirect_uri":redirect,"challenge":challenge,"state":q.get("state"),"resource":resource}),600)?;
    let path = format!("/auth/consent?pending={pending}");
    if session(&s, &h).is_err() {
        return Ok(login_redirect(&s, &path));
    }
    Ok(Redirect::to(&path).into_response())
}
async fn consent_page(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Query(q): Query<Fields>,
) -> WebResult<Response> {
    let pending = field(&q, "pending")?;
    let user = match session(&s, &h) {
        Ok(v) => v,
        Err(_) => {
            return Ok(login_redirect(
                &s,
                &format!("/auth/consent?pending={pending}"),
            ));
        }
    };
    let p = s
        .store
        .get("pending", pending)?
        .ok_or(ApiError::bad("expired_authorization"))?;
    let c = s
        .store
        .get("client", value_str(&p, "client_id")?)?
        .ok_or(ApiError::bad("invalid_client"))?;
    Ok(page("Authorize",format!("<p>Allow {} to control paired computers?</p><form method=post action=/auth/consent>{}<input type=hidden name=pending value=\"{}\"><button name=decision value=allow>Allow</button><button name=decision value=deny>Deny</button></form>",escaped(c["client_name"].as_str().unwrap_or("client")),csrf(&user),escaped(pending))).into_response())
}
async fn consent(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    authenticated_form(&s, &h, &f)?;
    let id = field(&f, "pending")?;
    let p = s
        .store
        .take("pending", id)?
        .ok_or(ApiError::bad("expired_authorization"))?;
    require(
        s.store
            .get("client", value_str(&p, "client_id")?)?
            .is_some(),
        "invalid_client",
    )?;
    let mut target =
        reqwest::Url::parse(value_str(&p, "redirect_uri")?).map_err(anyhow::Error::from)?;
    if f.get("decision").is_some_and(|s| s == "allow") {
        let code = random();
        s.store.put("code", &hash(&code), &p, 600)?;
        target.query_pairs_mut().append_pair("code", &code);
    } else {
        target
            .query_pairs_mut()
            .append_pair("error", "access_denied");
    }
    if let Some(state) = p["state"].as_str() {
        target.query_pairs_mut().append_pair("state", state);
    }
    target.query_pairs_mut().append_pair("iss", &s.origin);
    Ok(Redirect::to(target.as_str()).into_response())
}
fn validate_client(s: &Relay, f: &Fields) -> WebResult<Value> {
    let id = field(f, "client_id")?;
    let c = s
        .store
        .get("client", id)?
        .ok_or(ApiError::bad("invalid_client"))?;
    if c["token_endpoint_auth_method"] != "none" {
        require(
            ct(
                &hash(field(f, "client_secret")?),
                value_str(&c, "secretHash")?,
            ),
            "invalid_client",
        )?;
    }
    Ok(c)
}
fn mint(s: &Relay, client: &str, resource: &str) -> WebResult<Value> {
    let access = random();
    let refresh = random();
    let row = json!({"client_id":client,"resource":resource});
    s.store.put("access", &hash(&access), &row, 3600)?;
    s.store.put("refresh", &hash(&refresh), &row, 30 * 86400)?;
    Ok(
        json!({"access_token":access,"refresh_token":refresh,"token_type":"Bearer","expires_in":3600,"scope":"mcp:tools"}),
    )
}
async fn token(State(s): State<Arc<Relay>>, Form(f): Form<Fields>) -> WebResult<Json<Value>> {
    validate_client(&s, &f)?;
    let client = field(&f, "client_id")?;
    let row = match field(&f, "grant_type")? {
        "authorization_code" => {
            let key = hash(field(&f, "code")?);
            let row = s
                .store
                .get("code", &key)?
                .ok_or(ApiError::bad("invalid_grant"))?;
            require(
                row["client_id"] == client && row["redirect_uri"] == field(&f, "redirect_uri")?,
                "invalid_grant",
            )?;
            let verifier = field(&f, "code_verifier")?;
            require(
                (43..=128).contains(&verifier.len())
                    && verifier
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
                "invalid_grant",
            )?;
            let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
            require(
                ct(&challenge, value_str(&row, "challenge")?),
                "invalid_grant",
            )?;
            require(
                f.get("resource").is_none_or(|v| row["resource"] == *v),
                "invalid_target",
            )?;
            s.store
                .take("code", &key)?
                .ok_or(ApiError::bad("invalid_grant"))?
        }
        "refresh_token" => {
            let key = hash(field(&f, "refresh_token")?);
            let row = s
                .store
                .get("refresh", &key)?
                .ok_or(ApiError::bad("invalid_grant"))?;
            require(row["client_id"] == client, "invalid_grant")?;
            require(
                f.get("resource").is_none_or(|v| row["resource"] == *v),
                "invalid_target",
            )?;
            require(
                f.get("scope").is_none_or(|v| v == "mcp:tools"),
                "invalid_scope",
            )?;
            s.store
                .take("refresh", &key)?
                .ok_or(ApiError::bad("invalid_grant"))?
        }
        _ => return Err(ApiError::bad("unsupported_grant_type")),
    };
    Ok(Json(mint(&s, client, value_str(&row, "resource")?)?))
}
async fn revoke(State(s): State<Arc<Relay>>, Form(f): Form<Fields>) -> WebResult<Json<Value>> {
    validate_client(&s, &f)?;
    let client = field(&f, "client_id")?;
    let key = hash(field(&f, "token")?);
    for ns in ["access", "refresh"] {
        if s.store
            .get(ns, &key)?
            .is_some_and(|r| r["client_id"] == client)
        {
            s.store.delete(ns, &key)?;
        }
    }
    Ok(Json(json!({})))
}
async fn verify_page(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Query(q): Query<Fields>,
) -> WebResult<Response> {
    let user = match session(&s, &h) {
        Ok(v) => v,
        Err(_) => return Ok(login_redirect(&s, "/device/verify")),
    };
    Ok(page("Pair device",format!("<form method=post action=/device/approve>{}<label>Code <input name=user_code value=\"{}\"></label><button name=decision value=allow>Approve</button><button name=decision value=deny>Deny</button></form>",csrf(&user),escaped(q.get("user_code").map(String::as_str).unwrap_or_default()))).into_response())
}
async fn approve(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    authenticated_form(&s, &h, &f)?;
    let code = field(&f, "user_code")?;
    let (key, mut row) = s
        .store
        .list("pair")?
        .into_iter()
        .find(|(_, v)| v["user_code"] == code)
        .ok_or(ApiError::bad("expired_token"))?;
    row["approved"] = json!(f.get("decision").is_some_and(|v| v == "allow"));
    row["denied"] = json!(row["approved"] != true);
    require(s.store.update("pair", &key, &row)?, "expired_token")?;
    Ok(page(
        "Device decision",
        "<p>Decision saved. The agent will finish polling.</p>".into(),
    )
    .into_response())
}
async fn admin(State(s): State<Arc<Relay>>, h: HeaderMap) -> WebResult<Response> {
    let user = match session(&s, &h) {
        Ok(v) => v,
        Err(_) => return Ok(login_redirect(&s, "/admin")),
    };
    let mut html="<nav><a href=/device/verify>Pair device</a> · <a href=/auth/clients>OAuth clients</a></nav>".to_owned();
    let devices = s.listed_devices()?;
    for d in devices.as_array().expect("devices") {
        html += &format!(
            "<form method=post action=/admin/device>{}<input type=hidden name=device_id value=\"{}\"><input name=name value=\"{}\"><span>online={} paused={}</span><button name=action value=rename>Rename</button><button name=action value=pause>Pause</button><button name=action value=resume>Resume</button><button name=action value=delete>Revoke/delete</button></form>",
            csrf(&user),
            escaped(d["deviceId"].as_str().unwrap_or_default()),
            escaped(d["name"].as_str().unwrap_or_default()),
            d["online"],
            d["paused"]
        );
    }
    html += &format!(
        "<h2>Recent audit (metadata only)</h2><pre>{}</pre><form method=post action=/auth/logout>{}<button>Logout</button></form>",
        escaped(&s.store.recent_audit()?.to_string()),
        csrf(&user)
    );
    Ok(page("Devices", html).into_response())
}
async fn admin_device(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    authenticated_form(&s, &h, &f)?;
    let id = field(&f, "device_id")?;
    let mut row = s
        .store
        .get("device", id)?
        .ok_or(ApiError::bad("unknown_device"))?;
    match field(&f, "action")? {
        "rename" => {
            let name = field(&f, "name")?;
            require(!name.is_empty() && name.len() <= 80, "invalid_name")?;
            row["name"] = json!(name);
            require(s.store.update("device", id, &row)?, "unknown_device")?;
        }
        "pause" | "resume" => {
            row["paused"] = json!(field(&f, "action")? == "pause");
            require(s.store.update("device", id, &row)?, "unknown_device")?;
        }
        "delete" => {
            s.store
                .delete("device_token", value_str(&row, "tokenHash")?)?;
            s.store.delete("device", id)?;
            s.disconnect(id);
        }
        _ => return Err(ApiError::bad("invalid_action")),
    }
    Ok(Redirect::to("/admin").into_response())
}
async fn clients(State(s): State<Arc<Relay>>, h: HeaderMap) -> WebResult<Response> {
    let user = match session(&s, &h) {
        Ok(v) => v,
        Err(_) => return Ok(login_redirect(&s, "/auth/clients")),
    };
    let mut html = String::new();
    for (id, c) in s.store.list("client")? {
        html += &format!(
            "<form method=post action=/auth/clients/delete>{}<input type=hidden name=client_id value=\"{}\"><span>{}</span><button>Revoke client</button></form>",
            csrf(&user),
            escaped(&id),
            escaped(c["client_name"].as_str().unwrap_or_default())
        );
    }
    Ok(page("OAuth clients", html).into_response())
}
async fn delete_client(
    State(s): State<Arc<Relay>>,
    h: HeaderMap,
    Form(f): Form<Fields>,
) -> WebResult<Response> {
    authenticated_form(&s, &h, &f)?;
    let id = field(&f, "client_id")?;
    s.store.delete("client", id)?;
    for ns in ["access", "refresh", "code", "pending"] {
        for (key, row) in s.store.list(ns)? {
            if row["client_id"] == id {
                s.store.delete(ns, &key)?;
            }
        }
    }
    Ok(Redirect::to("/auth/clients").into_response())
}
