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

use std::collections::BTreeSet;

use anyhow::{Result, bail, ensure};
use config::meta::folder::{DEFAULT_FOLDER, FolderType};
use sea_orm::{ColumnTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait};

use super::{Action, Resource, ResourceKind, caller};
use crate::{
    db,
    table::entity::{alerts, folders},
};

/// Folder IDs the request caller may see; `None` means every folder of `folder_type`.
pub async fn visible_folders(
    organization: &str,
    folder_type: FolderType,
) -> Result<Option<BTreeSet<String>>> {
    if !super::enabled() {
        return Ok(None);
    }
    let subject = caller::current_subject().await?;
    visible_folders_for(&subject, organization, folder_type).await
}

/// Requires Write on every object and a visible destination, so one denial moves nothing.
pub async fn authorize_folder_move(
    organization: &str,
    folder_type: FolderType,
    ids: &[String],
    destination: &str,
) -> Result<()> {
    if !super::enabled() {
        return Ok(());
    }
    let kind = object_kind(folder_type)?;
    let subject = caller::current_subject().await?;
    let resources: Vec<_> = ids.iter().map(|id| Resource::new(kind, id)).collect();
    super::authorize_subject_all(&subject, organization, &[Action::Write], &resources).await?;
    let visible = visible_folders_for(&subject, organization, folder_type).await?;
    ensure!(super::readable(&visible, destination), "RBAC access denied");
    Ok(())
}

async fn visible_folders_for(
    subject: &str,
    organization: &str,
    folder_type: FolderType,
) -> Result<Option<BTreeSet<String>>> {
    let kind = object_kind(folder_type)?;
    let Some(readable) = super::readable_subject_object_ids(subject, organization, kind).await?
    else {
        return Ok(None);
    };
    let mut visible = BTreeSet::from([DEFAULT_FOLDER.to_owned()]);
    visible.extend(
        object_folders(organization, kind)
            .await?
            .into_iter()
            .filter(|(id, _)| readable.contains(id))
            .map(|(_, folder)| folder),
    );
    Ok(Some(visible))
}

fn object_kind(folder_type: FolderType) -> Result<ResourceKind> {
    match folder_type {
        FolderType::Dashboards => Ok(ResourceKind::Dashboard),
        FolderType::Alerts => Ok(ResourceKind::Alert),
        FolderType::Reports => Ok(ResourceKind::Report),
        _ => bail!("RBAC does not support this folder type"),
    }
}

async fn object_folders(organization: &str, kind: ResourceKind) -> Result<Vec<(String, String)>> {
    let conn = db::get_orm_client_rw().await;
    Ok(match kind {
        ResourceKind::Dashboard => crate::table::dashboards::list_ids_by_org(organization).await?,
        ResourceKind::Report => crate::table::reports::list_ids_by_org(conn, organization).await?,
        ResourceKind::Alert => {
            alerts::Entity::find()
                .select_only()
                .column(alerts::Column::Id)
                .column(folders::Column::FolderId)
                .join(JoinType::InnerJoin, alerts::Relation::Folders.def())
                .filter(alerts::Column::Org.eq(organization))
                .into_tuple::<(String, String)>()
                .all(conn)
                .await?
        }
        _ => bail!("RBAC does not support this folder type"),
    })
}
