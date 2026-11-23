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

use sea_orm::ConnectionTrait;

use super::*;

#[tokio::test]
async fn rbac_primary_token_binding_tracks_rotation_and_row_identity() {
    if std::env::var_os("O2_TOKEN_BINDING_CHILD").is_none() {
        let directory =
            std::env::temp_dir().join(format!("token-binding-{}", config::ider::uuid()));
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "table::org_ingestion_tokens::rbac_tests::rbac_primary_token_binding_tracks_rotation_and_row_identity", "--nocapture"])
            .env("O2_TOKEN_BINDING_CHILD", "1").env("ZO_DATA_DIR", &directory)
            .env("ZO_META_STORE", "sqlite").status().unwrap();
        if directory.exists() {
            std::fs::remove_dir_all(directory).unwrap();
        }
        assert!(status.success());
        return;
    }
    std::fs::create_dir_all(&config::get_config().common.data_db_dir).unwrap();
    let client = get_orm_client_rw().await;
    let schema = sea_orm::Schema::new(client.get_database_backend());
    client
        .execute(
            client
                .get_database_backend()
                .build(&schema.create_table_from_entity(Entity)),
        )
        .await
        .unwrap();
    let mut row = OrgIngestionTokenRecord {
        id: config::ider::uuid(),
        org_id: "token-org".into(),
        name: "collector".into(),
        token: "o2oi_original".into(),
        description: String::new(),
        is_default: false,
        enabled: true,
        created_by: "admin@example.test".into(),
        created_at: 1,
        updated_at: 1,
        splunk_token: Some(None),
    };
    add(&row).await.unwrap();
    let original_id = row.id.clone();
    assert_eq!(
        find_enabled_token_primary(&row.org_id, &row.token)
            .await
            .unwrap()
            .unwrap()
            .id,
        original_id
    );
    assert!(
        find_enabled_token_primary("other-org", &row.token)
            .await
            .unwrap()
            .is_none()
    );
    let rotated = rotate_token(&row.org_id, &row.name).await.unwrap();
    assert!(
        find_enabled_token_primary(&row.org_id, &row.token)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        find_enabled_token_primary(&row.org_id, &rotated)
            .await
            .unwrap()
            .unwrap()
            .id,
        original_id
    );
    set_enabled(&row.org_id, &row.name, false).await.unwrap();
    assert!(
        find_enabled_token_primary(&row.org_id, &rotated)
            .await
            .unwrap()
            .is_none()
    );
    delete_by_org(&row.org_id).await.unwrap();
    row.id = config::ider::uuid();
    row.token = "o2oi_recreated".into();
    add(&row).await.unwrap();
    assert_ne!(
        find_enabled_token_primary(&row.org_id, &row.token)
            .await
            .unwrap()
            .unwrap()
            .id,
        original_id
    );
    delete_by_org(&row.org_id).await.unwrap();
    row.name = "_o2_feature".into();
    row.created_by = WRITER_TOKEN_CREATOR.into();
    add(&row).await.unwrap();
    assert!(
        find_enabled_token_primary(&row.org_id, &row.token)
            .await
            .unwrap()
            .is_none()
    );
}
