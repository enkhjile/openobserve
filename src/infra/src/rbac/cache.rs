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

use std::sync::{Arc, LazyLock};

use anyhow::Result;
use hashlink::LinkedHashMap;
use openobserve_rbac::{Engine, PolicyDocument};
use parking_lot::RwLock;

static CACHE: LazyLock<PolicyCache> = LazyLock::new(PolicyCache::default);

#[derive(Default)]
struct PolicyCache {
    entries: RwLock<LinkedHashMap<String, (PolicyDocument, Arc<Engine>)>>,
}

impl PolicyCache {
    async fn get(&self, document: &PolicyDocument, capacity: usize) -> Result<Arc<Engine>> {
        if capacity == 0 {
            return Ok(Arc::new(Engine::new(document).await?));
        }
        if let Some((stored, engine)) = self.entries.read().get(&document.organization)
            && stored == document
        {
            return Ok(engine.clone());
        }
        let compiled = Arc::new(Engine::new(document).await?);
        let mut entries = self.entries.write();
        entries.insert(
            document.organization.clone(),
            (document.clone(), compiled.clone()),
        );
        while entries.len() > capacity {
            entries.pop_front();
        }
        Ok(compiled)
    }
}

pub(super) async fn engine(document: &PolicyDocument) -> Result<Arc<Engine>> {
    CACHE
        .get(
            document,
            config::get_config().common.rbac_policy_cache_entries,
        )
        .await
}

#[cfg(test)]
mod tests {
    use openobserve_rbac::{Action, Grant, Resource, Role};

    use super::*;

    #[tokio::test]
    async fn rbac_compiled_policy_requires_exact_authoritative_content() {
        let cache = PolicyCache::default();
        let subject = "a7b93c01-169d-4e95-a542-e6b48c929046";
        let mut document = PolicyDocument {
            schema_version: 1,
            version: 1,
            organization: "first".into(),
            grants: vec![Grant {
                subject: subject.into(),
                role: Role::Viewer,
                resources: vec![Resource::stream("logs", "audit")],
            }],
            destination_approvals: vec![],
        };
        let first = cache.get(&document, 1).await.unwrap();
        assert!(Arc::ptr_eq(&first, &cache.get(&document, 1).await.unwrap()));
        document.grants[0].resources = vec![Resource::stream("logs", "other")];
        let revoked = cache.get(&document, 1).await.unwrap();
        assert!(
            !revoked
                .authorize(
                    subject,
                    "first",
                    Action::Query,
                    &Resource::stream("logs", "audit")
                )
                .unwrap()
        );
        document.organization = "second".into();
        cache.get(&document, 1).await.unwrap();
        assert!(!cache.entries.read().contains_key("first"));
        assert!(!Arc::ptr_eq(
            &cache.get(&document, 0).await.unwrap(),
            &cache.get(&document, 1).await.unwrap()
        ));
    }
}
