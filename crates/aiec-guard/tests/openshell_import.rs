//! Behavioural tests for the OpenShell importer: what converts, what is
//! reported, and what refuses the whole import.

use aiec_guard::{
    l7,
    openshell::{self, ImportFailure},
    policy::GuardPolicy,
};

fn import(document: &str) -> Result<openshell::ImportedPolicy, ImportFailure> {
    openshell::import_openshell(document)
}

fn fatal_fields(failure: &ImportFailure) -> Vec<&str> {
    failure
        .report
        .unsupported
        .iter()
        .filter(|field| field.fatal)
        .map(|field| field.field.as_str())
        .collect()
}

#[test]
fn a_rest_policy_converts_and_names_every_field_it_dropped() {
    let document = r#"
version: 1
network_policies:
  registry:
    endpoints:
      - host: registry.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
"#;
    let imported = import(document).expect("the policy converts");
    let policy: &GuardPolicy = &imported.policy;

    let rule = policy
        .network
        .egress
        .iter()
        .find(|rule| rule.host == "registry.example.com")
        .expect("the endpoint converted");
    assert_eq!(rule.port, 443);
    assert_eq!(
        rule.allowed_methods,
        vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
    );
    assert!(
        rule.allowed_paths.is_empty(),
        "read-only permits every path"
    );
    assert!(
        policy
            .network
            .dns
            .allowed_zones
            .contains(&"registry.example.com".to_owned())
    );
    // The converted policy is a policy Guard will accept, not just a shape.
    policy.validate().expect("converted policy is valid");
    GuardPolicy::from_yaml(&openshell::to_yaml(policy).expect("serializes"))
        .expect("the converted document parses back as a Guard policy");

    assert!(
        imported
            .report
            .converted
            .iter()
            .any(|entry| entry.field.ends_with(".enforcement")
                && entry.mapped_to.contains("always enforced"))
    );
    assert!(
        imported
            .report
            .converted
            .iter()
            .any(|entry| entry.field.ends_with(".binaries")
                && entry.mapped_to.contains("unrestricted")),
        "a source rule with no binaries clause is reported, not silently assumed"
    );
    let non_fatal: Vec<&str> = imported
        .report
        .unsupported
        .iter()
        .filter(|field| !field.fatal)
        .map(|field| field.field.as_str())
        .collect();
    assert_eq!(non_fatal, vec!["network_policies.*.dns"]);
    assert!(!imported.report.is_refused());
}

#[test]
fn an_mcp_policy_converts_into_rules_that_govern_a_real_request() {
    let document = r#"
version: 1
network_policies:
  tools:
    endpoints:
      - host: tools.example.com
        port: 443
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: tools/list
          - allow:
              method: tools/call
              tool:
                any: [read_file, search]
        deny_rules:
          - method: tools/call
            tool: send_email
"#;
    let imported = import(document).expect("the policy converts");
    let l7 = imported.l7.expect("body rules convert");
    assert_eq!(
        l7.mcp.allowed_tools,
        vec!["read_file".to_owned(), "search".to_owned()]
    );
    assert_eq!(l7.mcp.denied_tools, vec!["send_email".to_owned()]);
    assert!(l7.mcp.allowed_methods.contains(&"tools/list".to_owned()));

    fn request(body: &str) -> l7::VisibleRequest<'_> {
        l7::VisibleRequest {
            host: "tools.example.com",
            method: "POST",
            path: "/mcp",
            content_type: Some("application/json"),
            body: Some(body.as_bytes()),
        }
    }
    let listed = l7::request_verdict(
        Some(&l7),
        &request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
    );
    assert!(listed.allowed(), "{listed:?}");
    let read = l7::request_verdict(
        Some(&l7),
        &request(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}"#),
    );
    assert!(read.allowed(), "{read:?}");
    let wrote = l7::request_verdict(
        Some(&l7),
        &request(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email"}}"#,
        ),
    );
    assert!(
        !wrote.allowed(),
        "a denied tool stays denied after conversion"
    );
}

#[test]
fn a_binary_scoped_rule_refuses_the_import_and_says_which_field() {
    let document = r#"
version: 1
network_policies:
  registry:
    endpoints:
      - host: registry.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/npm
      - path: /usr/bin/node
"#;
    let failure = import(document).expect_err("binary scoping cannot be honoured");
    assert!(
        fatal_fields(&failure).contains(&"network_policies.registry.binaries"),
        "{failure}"
    );
    let rendered = failure.to_string();
    assert!(rendered.contains("binaries"), "{rendered}");
    assert!(rendered.contains("outside the guest"), "{rendered}");
}

#[test]
fn an_audit_only_rule_is_refused_because_guard_cannot_merely_report_one() {
    let document = r#"
version: 1
network_policies:
  registry:
    endpoints:
      - host: registry.example.com
        port: 443
        protocol: rest
        access: read-only
"#;
    let failure = import(document).expect_err("the default is audit, which Guard cannot be");
    assert!(fatal_fields(&failure).contains(&"network_policies.registry.endpoints[0].enforcement"));
    assert!(failure.to_string().contains("audit"), "{failure}");
}

#[test]
fn an_exact_path_rule_is_refused_rather_than_widened_to_a_prefix() {
    let document = r#"
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /v1/download
"#;
    let failure = import(document).expect_err("an exact path is not a prefix");
    assert!(
        fatal_fields(&failure).contains(&"network_policies.api.endpoints[0].rules[0].allow.path"),
        "{failure}"
    );
    assert!(
        failure.to_string().contains("/v1/download/..."),
        "the refusal says what converting would have admitted: {failure}"
    );
}

#[test]
fn a_prefix_glob_converts_to_the_same_paths() {
    let document = r#"
version: 1
network_policies:
  repos:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/**
"#;
    let imported = import(document).expect("a prefix glob converts");
    let rule = imported
        .policy
        .network
        .egress
        .iter()
        .find(|rule| rule.host == "api.example.com")
        .expect("converted");
    assert_eq!(rule.allowed_paths, vec!["/repos/".to_owned()]);
    assert_eq!(rule.allowed_methods, vec!["GET".to_owned()]);
}

#[test]
fn a_graphql_endpoint_that_forbids_queries_is_refused() {
    let document = r#"
version: 1
network_policies:
  issues:
    endpoints:
      - host: issues.example.com
        port: 443
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: mutation
"#;
    let failure = import(document).expect_err("mutation-only cannot be expressed");
    assert!(
        fatal_fields(&failure).contains(&"network_policies.issues.endpoints[0].rules"),
        "{failure}"
    );
    assert!(failure.to_string().contains("mutation"), "{failure}");
}

#[test]
fn a_read_only_graphql_endpoint_converts_to_a_mutation_deny() {
    let document = r#"
version: 1
network_policies:
  issues:
    endpoints:
      - host: issues.example.com
        port: 443
        protocol: graphql
        enforcement: enforce
        access: read-only
"#;
    let imported = import(document).expect("read-only converts");
    let l7 = imported.l7.expect("graphql rules convert");
    assert!(!l7.graphql.allow_mutations);
    let mutation = l7::graphql_verdict(&l7.graphql, "mutation Delete { deleteIssue { id } }");
    assert!(!mutation.allowed());
    let query = l7::graphql_verdict(&l7.graphql, "query Read { viewer { login } }");
    assert!(query.allowed());
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    let document = r#"
version: 1
network_policies:
  registry:
    endpoints:
      - host: registry.example.com
        port: 443
        protocol: tcp
future_feature: true
"#;
    let failure = import(document).expect_err("an unknown top-level field is refused");
    assert!(
        failure
            .document_error
            .as_deref()
            .is_some_and(|error| error.contains("future_feature")),
        "{failure:?}"
    );
}

#[test]
fn a_document_that_is_not_an_openshell_policy_is_refused_with_a_reason() {
    let failure = import("this is not: [a policy").expect_err("unreadable document");
    assert!(failure.document_error.is_some());
    assert!(failure.report.schema_reference.contains("OpenShell"));
}

#[test]
fn two_endpoints_with_different_body_rules_cannot_become_one_attachment_scope() {
    let document = r#"
version: 1
network_policies:
  first:
    endpoints:
      - host: first.example.com
        port: 443
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: tools/list
  second:
    endpoints:
      - host: second.example.com
        port: 443
        protocol: mcp
        enforcement: enforce
        rules:
          - allow:
              method: tools/call
              tool: read_file
"#;
    let failure = import(document).expect_err("per-endpoint body rules are not expressible");
    assert!(failure.to_string().contains("per attachment"), "{failure}");
}

#[test]
fn a_destination_only_tcp_endpoint_converts_without_inventing_method_rules() {
    let document = r#"
version: 1
network_policies:
  database:
    endpoints:
      - host: db.example.com
        port: 5432
        protocol: tcp
        enforcement: enforce
    binaries: []
"#;
    let imported = import(document).expect("tcp converts");
    let rule = imported
        .policy
        .network
        .egress
        .iter()
        .find(|rule| rule.host == "db.example.com")
        .expect("converted");
    assert_eq!(rule.port, 5432);
    assert!(rule.allowed_methods.is_empty());
    assert!(
        imported
            .report
            .converted
            .iter()
            .any(|entry| entry.field.ends_with(".binaries")
                && entry.mapped_to.contains("matches no binary")),
        "dropping a rule that matches no binary is reported, not silent"
    );
}
