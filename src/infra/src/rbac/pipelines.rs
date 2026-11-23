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

use anyhow::{Result, ensure};

use super::{Action, Resource};

pub async fn authorize_pipeline_permissions(
    org: &str,
    permissions: &[(String, Action, Resource)],
) -> Result<()> {
    let mut subjects = std::collections::HashSet::new();
    for (subject, ..) in permissions {
        if subjects.insert(subject) {
            super::validate_subject(subject, org).await?;
        }
    }
    let document = super::read_policy(org).await?;
    let engine = super::cache::engine(&document).await?;
    for (subject, action, resource) in permissions {
        ensure!(
            engine.authorize(subject, org, *action, resource)?,
            "Pipeline access denied"
        );
    }
    Ok(())
}
