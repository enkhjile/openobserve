// Copyright 2026 OpenObserve Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use openobserve_rbac::{Action, Engine, Grant, PolicyDocument, Resource, ResourceKind, Role};

fn policy(role: Role, resources: Vec<Resource>) -> PolicyDocument {
    PolicyDocument {
        destination_approvals: vec![],
        schema_version: 1,
        version: 1,
        organization: "a".into(),
        grants: vec![Grant {
            subject: "uuid-alice".into(),
            role,
            resources,
        }],
    }
}

#[tokio::test]
async fn roles_and_isolation() {
    let stream = Resource::stream("logs", "api");
    for (role, allowed) in [
        (
            Role::Admin,
            vec![Action::Query, Action::Ingest, Action::Delete],
        ),
        (Role::Editor, vec![Action::Query]),
        (Role::Viewer, vec![Action::Query]),
        (Role::Ingester, vec![Action::Ingest]),
    ] {
        let engine = Engine::new(&policy(role, vec![stream.clone()]))
            .await
            .unwrap();
        for action in [Action::Query, Action::Ingest, Action::Delete] {
            assert_eq!(
                engine
                    .authorize("uuid-alice", "a", action, &stream)
                    .unwrap(),
                allowed.contains(&action)
            );
        }
        assert!(
            !engine
                .authorize("uuid-alice", "b", Action::Query, &stream)
                .unwrap()
        );
        assert!(
            !engine
                .authorize("uuid-bob", "a", Action::Query, &stream)
                .unwrap()
        );
        assert!(
            !engine
                .authorize(
                    "uuid-alice",
                    "a",
                    Action::Query,
                    &Resource::stream("logs", "finance")
                )
                .unwrap()
        );
        assert!(
            !engine
                .authorize(
                    "uuid-alice",
                    "a",
                    Action::Query,
                    &Resource::stream("metrics", "api")
                )
                .unwrap()
        );
    }
}

#[tokio::test]
async fn role_administration_and_mutations() {
    let viewer = Engine::new(&policy(
        Role::Viewer,
        vec![Resource::new(ResourceKind::Dashboard, "*")],
    ))
    .await
    .unwrap();
    assert!(
        viewer
            .authorize(
                "uuid-alice",
                "a",
                Action::Read,
                &Resource::new(ResourceKind::Dashboard, "d")
            )
            .unwrap()
    );
    assert!(
        !viewer
            .authorize(
                "uuid-alice",
                "a",
                Action::Write,
                &Resource::new(ResourceKind::Dashboard, "d")
            )
            .unwrap()
    );
    let editor = Engine::new(&policy(Role::Editor, vec![Resource::organization()]))
        .await
        .unwrap();
    assert!(
        !editor
            .authorize("uuid-alice", "a", Action::Manage, &Resource::organization())
            .unwrap()
    );
    let admin = Engine::new(&policy(Role::Admin, vec![Resource::organization()]))
        .await
        .unwrap();
    assert!(
        admin
            .authorize("uuid-alice", "a", Action::Manage, &Resource::organization())
            .unwrap()
    );
    assert!(
        !admin
            .authorize("uuid-alice", "b", Action::Manage, &Resource::organization())
            .unwrap()
    );
}

#[tokio::test]
async fn invalid_and_empty_policies_fail_closed() {
    assert!(
        Engine::new(&policy(Role::Ingester, vec![Resource::stream("logs", "*")]))
            .await
            .is_err()
    );
    let mut empty = policy(Role::Viewer, vec![]);
    empty.grants.clear();
    assert!(Engine::new(&empty).await.is_err());
    let mut bad = policy(Role::Viewer, vec![Resource::stream("logs", "api")]);
    bad.schema_version = 2;
    assert!(Engine::new(&bad).await.is_err());
}

#[tokio::test]
async fn collection_scope_cannot_be_satisfied_by_one_stream() {
    let stream = Resource::stream("logs", "api");
    let engine = Engine::new(&policy(Role::Viewer, vec![stream]))
        .await
        .unwrap();
    assert!(
        !engine
            .authorize(
                "uuid-alice",
                "a",
                Action::Read,
                &Resource::stream("logs", "*")
            )
            .unwrap()
    );
    let engine = Engine::new(&policy(Role::Viewer, vec![Resource::stream("logs", "*")]))
        .await
        .unwrap();
    assert!(
        engine
            .authorize(
                "uuid-alice",
                "a",
                Action::Read,
                &Resource::stream("logs", "*")
            )
            .unwrap()
    );
}

#[tokio::test]
async fn multiple_roles_do_not_cross_contaminate_resource_scopes() {
    let mut document = policy(Role::Viewer, vec![Resource::stream("logs", "finance")]);
    document.grants.push(Grant {
        subject: "uuid-alice".into(),
        role: Role::Ingester,
        resources: vec![Resource::stream("logs", "api")],
    });
    let engine = Engine::new(&document).await.unwrap();
    assert!(
        !engine
            .authorize(
                "uuid-alice",
                "a",
                Action::Ingest,
                &Resource::stream("logs", "finance")
            )
            .unwrap()
    );
    assert!(
        !engine
            .authorize(
                "uuid-alice",
                "a",
                Action::Query,
                &Resource::stream("logs", "api")
            )
            .unwrap()
    );
    assert!(
        !engine
            .authorize(
                "uuid-alice",
                "a",
                Action::Export,
                &Resource::stream("logs", "finance")
            )
            .unwrap()
    );
    document.grants.remove(0);
    let revoked = Engine::new(&document).await.unwrap();
    assert!(
        !revoked
            .authorize(
                "uuid-alice",
                "a",
                Action::Query,
                &Resource::stream("logs", "finance")
            )
            .unwrap()
    );
}

#[tokio::test]
async fn exports_require_explicit_role_permission_on_each_source() {
    for (role, can_export) in [
        (Role::Admin, true),
        (Role::Viewer, false),
        (Role::Editor, false),
    ] {
        let stream = Resource::stream("logs", "permitted");
        let engine = Engine::new(&policy(role, vec![stream.clone()]))
            .await
            .unwrap();
        assert!(
            engine
                .authorize("uuid-alice", "a", Action::Query, &stream)
                .unwrap()
        );
        assert_eq!(
            engine
                .authorize("uuid-alice", "a", Action::Export, &stream)
                .unwrap(),
            can_export
        );
        assert!(
            !engine
                .authorize(
                    "uuid-alice",
                    "a",
                    Action::Export,
                    &Resource::stream("logs", "secret")
                )
                .unwrap()
        );
    }
}

#[test]
fn legacy_policy_serialization_preserves_cas_and_defaults_to_no_delivery() {
    let document = policy(Role::Admin, vec![Resource::organization()]);
    let encoded = serde_json::to_value(&document).unwrap();
    assert!(encoded.get("destination_approvals").is_none());
    let decoded: PolicyDocument = serde_json::from_value(encoded.clone()).unwrap();
    assert!(decoded.destination_approvals.is_empty());
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
}

#[tokio::test]
async fn token_namespace_cannot_escalate_or_use_malformed_ids() {
    let valid = "org-token:000000000000000000000000001";
    for (subject, role, resources) in [
        (valid, Role::Admin, vec![Resource::organization()]),
        (valid, Role::Viewer, vec![Resource::stream("logs", "api")]),
        (
            "org-token:",
            Role::Ingester,
            vec![Resource::stream("logs", "api")],
        ),
        (
            "org-token:short",
            Role::Ingester,
            vec![Resource::stream("logs", "api")],
        ),
        (
            "other:000000000000000000000000001",
            Role::Ingester,
            vec![Resource::stream("logs", "api")],
        ),
    ] {
        let mut document = policy(role, resources);
        document.grants[0].subject = subject.into();
        assert!(
            Engine::new(&document).await.is_err(),
            "accepted {subject} {role:?}"
        );
    }
    let mut document = policy(Role::Ingester, vec![Resource::stream("logs", "api")]);
    document.grants[0].subject = valid.into();
    let engine = Engine::new(&document).await.unwrap();
    assert!(
        engine
            .authorize(valid, "a", Action::Ingest, &Resource::stream("logs", "api"))
            .unwrap()
    );
    assert!(
        !engine
            .authorize(valid, "a", Action::Query, &Resource::stream("logs", "api"))
            .unwrap()
    );
}

#[tokio::test]
async fn exporter_can_only_read_query_and_export_explicit_streams() {
    let role: Role = serde_json::from_str(r#""exporter""#).unwrap();
    let source = Resource::stream("logs", "api");
    let engine = Engine::new(&policy(role, vec![source.clone()]))
        .await
        .unwrap();
    for (action, expected) in [
        (Action::Read, true),
        (Action::Query, true),
        (Action::Export, true),
        (Action::Write, false),
        (Action::Manage, false),
        (Action::Ingest, false),
        (Action::Delete, false),
    ] {
        assert_eq!(
            engine
                .authorize("uuid-alice", "a", action, &source)
                .unwrap(),
            expected
        );
    }
    for scope in [Resource::stream("logs", "*"), Resource::organization()] {
        assert!(Engine::new(&policy(role, vec![scope])).await.is_err());
    }
}

#[tokio::test]
async fn report_authorship_and_export_are_separate_grants() {
    let report = Resource::new(ResourceKind::Report, "daily");
    for (role, may_edit) in [(Role::Viewer, false), (Role::Editor, true)] {
        let engine = Engine::new(&policy(role, vec![report.clone()]))
            .await
            .unwrap();
        assert!(
            engine
                .authorize("uuid-alice", "a", Action::Read, &report)
                .unwrap()
        );
        assert_eq!(
            engine
                .authorize("uuid-alice", "a", Action::Write, &report)
                .unwrap(),
            may_edit
        );
        assert_eq!(
            engine
                .authorize("uuid-alice", "a", Action::Delete, &report)
                .unwrap(),
            may_edit
        );
        assert!(
            !engine
                .authorize(
                    "uuid-alice",
                    "a",
                    Action::Export,
                    &Resource::stream("logs", "api")
                )
                .unwrap()
        );
    }
}
