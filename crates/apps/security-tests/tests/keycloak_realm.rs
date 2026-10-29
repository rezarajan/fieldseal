//! The Keycloak realm of the local stack (`deploy/local/keycloak/fieldseal-realm.json`) as the
//! operator sign-in needs it (REG-070a, Technical Plan 7.5): the factory API audience reaches
//! access tokens and no ID token, and the CLI is a public PKCE client. A test cannot start
//! Keycloak, so it reads the file; `just up` imports the same file.

use serde_json::Value;

const API_AUDIENCE: &str = "fieldseal-factory-api";

fn realm() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../deploy/local/keycloak/fieldseal-realm.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("the realm file")).expect("the realm file is JSON")
}

fn clients(realm: &Value) -> &Vec<Value> {
    realm["clients"].as_array().expect("clients")
}

fn client<'a>(realm: &'a Value, id: &str) -> &'a Value {
    clients(realm).iter().find(|c| c["clientId"] == id).unwrap_or_else(|| panic!("client {id}"))
}

fn mappers(client: &Value) -> Vec<&Value> {
    client["protocolMappers"].as_array().map(|m| m.iter().collect()).unwrap_or_default()
}

/// The mappers that put `audience` into a token: an audience mapper naming it, or a claim
/// mapper that writes `aud`.
fn audience_mappers(client: &Value) -> Vec<&Value> {
    mappers(client)
        .into_iter()
        .filter(|m| m["config"]["included.custom.audience"] == API_AUDIENCE || m["config"]["included.client.audience"] == API_AUDIENCE || m["config"]["claim.value"] == API_AUDIENCE)
        .collect()
}

#[test]
fn reg_070a_the_api_audience_mapper_adds_to_the_access_token_only() {
    let realm = realm();
    let found = audience_mappers(client(&realm, "fieldseal-cli"));
    assert_eq!(found.len(), 1, "one mapper adds the API audience to fieldseal-cli tokens");
    assert_eq!(found[0]["protocolMapper"], "oidc-audience-mapper");
    assert_eq!(found[0]["config"]["access.token.claim"], "true");
    assert_eq!(found[0]["config"]["id.token.claim"], "false");
}

#[test]
fn reg_070a_no_client_puts_the_api_audience_in_an_id_token() {
    let realm = realm();
    for c in clients(&realm) {
        for m in audience_mappers(c) {
            assert_ne!(m["config"]["id.token.claim"], "true", "client {} puts the API audience in its ID token", c["clientId"]);
        }
        // Only the CLI's access token is for the API: the portals' are not.
        if c["clientId"] != "fieldseal-cli" {
            assert!(audience_mappers(c).is_empty(), "client {} must not carry the API audience at all", c["clientId"]);
        }
    }
    // A realm-wide client scope could add it to every client; the realm declares none.
    assert!(realm.get("clientScopes").is_none_or(|s| s.as_array().is_some_and(Vec::is_empty)), "a realm client scope would reach every client");
    assert!(realm.get("defaultDefaultClientScopes").is_none());
}

#[test]
fn reg_070a_fieldseal_cli_is_a_public_client_with_pkce_s256() {
    let realm = realm();
    let cli = client(&realm, "fieldseal-cli");
    assert_eq!(cli["publicClient"], true);
    assert!(cli.get("secret").is_none(), "a public client has no secret");
    assert_eq!(cli["standardFlowEnabled"], true);
    for flow in ["implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"] {
        assert_eq!(cli[flow], false, "{flow}");
    }
    assert_eq!(cli["attributes"]["pkce.code.challenge.method"], "S256", "PKCE S256 is required");
    assert_eq!(cli["redirectUris"], serde_json::json!(["http://127.0.0.1/*"]));
    // The roles and acr reach the access token the factory reads.
    let by_type = |t: &str| mappers(cli).into_iter().find(|m| m["protocolMapper"] == t).unwrap_or_else(|| panic!("mapper {t}")).clone();
    assert_eq!(by_type("oidc-usermodel-realm-role-mapper")["config"]["claim.name"], "roles");
    assert_eq!(by_type("oidc-usermodel-realm-role-mapper")["config"]["access.token.claim"], "true");
    assert_eq!(by_type("oidc-acr-mapper")["config"]["access.token.claim"], "true");
    assert_eq!(cli["attributes"]["acr.loa.map"], "{\"phr\":\"2\"}", "the passkey level is the one that maps to phr");
}

#[test]
fn reg_070a_product_owner_has_a_fixed_id() {
    let realm = realm();
    let user = realm["users"].as_array().expect("users").iter().find(|u| u["username"] == "product-owner").expect("product-owner");
    assert_eq!(user["id"], "00000000-0000-4000-8000-000000000003");
}
