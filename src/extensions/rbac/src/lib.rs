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

use anyhow::{Context, Result, ensure};
use casbin::{CoreApi, DefaultModel, Enforcer, MemoryAdapter, MgmtApi};
use serde::{Deserialize, Serialize};

const MODEL: &str = include_str!("../model.conf");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Delete,
    Query,
    Export,
    Ingest,
    Manage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Organization,
    Stream,
    Dashboard,
    Alert,
    Pipeline,
    Report,
    SavedQuery,
    ServiceAccount,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub kind: ResourceKind,
    pub stream_type: String,
    pub name: String,
}

impl Resource {
    pub fn organization() -> Self {
        Self::new(ResourceKind::Organization, "organization")
    }
    pub fn new(kind: ResourceKind, name: &str) -> Self {
        Self {
            kind,
            stream_type: String::new(),
            name: name.into(),
        }
    }
    pub fn stream(stream_type: &str, name: &str) -> Self {
        Self {
            kind: ResourceKind::Stream,
            stream_type: stream_type.into(),
            name: name.into(),
        }
    }
    fn validate(&self, request: bool) -> Result<()> {
        ensure!(
            !self.name.is_empty() && !self.name.contains(['/', '\0']),
            "invalid resource name"
        );
        if self.kind == ResourceKind::Stream {
            ensure!(
                matches!(
                    self.stream_type.as_str(),
                    "logs" | "metrics" | "traces" | "enrichment_tables" | "index" | "metadata"
                ) || (!request && self.stream_type == "*"),
                "invalid stream type"
            );
        } else {
            ensure!(
                self.kind != ResourceKind::Organization || self.name == "organization",
                "invalid organization resource"
            );
            ensure!(
                self.stream_type.is_empty(),
                "non-stream resource has stream type"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    Editor,
    Viewer,
    Ingester,
    Exporter,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub subject: String,
    pub role: Role,
    pub resources: Vec<Resource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationApproval {
    pub destination_id: String,
    pub destination_name: String,
    pub target_fingerprint: String,
    pub sources: Vec<Resource>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u32,
    pub version: u64,
    pub organization: String,
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_approvals: Vec<DestinationApproval>,
}

impl PolicyDocument {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.version > 0,
            "unsupported policy version"
        );
        ensure!(
            !self.organization.is_empty() && !self.organization.contains(['/', '*', '\0']),
            "invalid organization"
        );
        ensure!(!self.grants.is_empty(), "policy has no grants");
        for approval in &self.destination_approvals {
            ensure!(
                !approval.destination_id.is_empty() && !approval.destination_name.is_empty(),
                "invalid destination identity"
            );
            ensure!(
                approval.target_fingerprint.len() == 64
                    && approval
                        .target_fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit()),
                "invalid destination fingerprint"
            );
            ensure!(
                !approval.sources.is_empty(),
                "destination requires source streams"
            );
            for source in &approval.sources {
                source.validate(true)?;
                ensure!(
                    source.kind == ResourceKind::Stream
                        && source.name != "*"
                        && source.stream_type != "*",
                    "destination requires exact streams"
                );
            }
        }
        for grant in &self.grants {
            if token_subject_id(&grant.subject)?.is_some() {
                ensure!(
                    grant.role == Role::Ingester,
                    "token subjects require the ingester role"
                );
            }
            ensure!(
                !grant.subject.is_empty() && !grant.subject.contains(['@', '*', '\0']),
                "invalid stable subject"
            );
            ensure!(!grant.resources.is_empty(), "grant has no resources");
            for resource in &grant.resources {
                resource.validate(false)?;
                if matches!(grant.role, Role::Ingester | Role::Exporter) {
                    ensure!(
                        resource.kind == ResourceKind::Stream
                            && resource.name != "*"
                            && resource.stream_type != "*",
                        "role requires explicit streams"
                    );
                }
            }
        }
        Ok(())
    }
}

pub struct Engine {
    enforcer: Enforcer,
}

impl Engine {
    pub async fn new(document: &PolicyDocument) -> Result<Self> {
        document.validate()?;
        let model = DefaultModel::from_str(MODEL).await?;
        let mut enforcer = Enforcer::new(model, MemoryAdapter::default()).await?;
        enforcer.enable_auto_save(false);
        for (index, grant) in document.grants.iter().enumerate() {
            let scoped_role = format!("grant:{index}");
            enforcer
                .add_grouping_policy(vec![
                    grant.subject.clone(),
                    scoped_role.clone(),
                    document.organization.clone(),
                ])
                .await?;
            for resource in &grant.resources {
                for action in actions(grant.role, resource.kind) {
                    let organization_admin =
                        grant.role == Role::Admin && resource.kind == ResourceKind::Organization;
                    let (kind, stream_type, name) = if organization_admin {
                        ("*".into(), "*".into(), "*".into())
                    } else {
                        (
                            format!("{:?}", resource.kind),
                            resource.stream_type.clone(),
                            resource.name.clone(),
                        )
                    };
                    enforcer
                        .add_policy(vec![
                            scoped_role.clone(),
                            document.organization.clone(),
                            kind,
                            stream_type,
                            name,
                            format!("{action:?}"),
                        ])
                        .await?;
                }
            }
        }
        Ok(Self { enforcer })
    }

    pub fn authorize(
        &self,
        subject: &str,
        organization: &str,
        action: Action,
        resource: &Resource,
    ) -> Result<bool> {
        resource.validate(true)?;
        Ok(self.enforcer.enforce((
            subject,
            organization,
            format!("{:?}", resource.kind),
            resource.stream_type.as_str(),
            resource.name.as_str(),
            format!("{action:?}"),
        ))?)
    }
}

pub fn token_subject_id(subject: &str) -> Result<Option<&str>> {
    if !subject.contains(':') {
        return Ok(None);
    }
    let id = subject
        .strip_prefix("org-token:")
        .context("unknown subject namespace")?;
    ensure!(
        id.len() == 27 && id.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid ingestion token identity"
    );
    Ok(Some(id))
}

fn actions(role: Role, kind: ResourceKind) -> &'static [Action] {
    use Action::{Delete, Export, Ingest, Manage, Query, Read, Write};
    match role {
        Role::Admin => &[Read, Write, Delete, Query, Export, Ingest, Manage],
        Role::Ingester => &[Ingest],
        Role::Exporter => &[Read, Query, Export],
        Role::Viewer => match kind {
            ResourceKind::Stream => &[Read, Query],
            ResourceKind::Dashboard
            | ResourceKind::Alert
            | ResourceKind::SavedQuery
            | ResourceKind::Report => &[Read],
            _ => &[],
        },
        Role::Editor => match kind {
            ResourceKind::Stream => &[Read, Query],
            ResourceKind::Dashboard
            | ResourceKind::Alert
            | ResourceKind::SavedQuery
            | ResourceKind::Report => &[Read, Write, Delete],
            _ => &[],
        },
    }
}
