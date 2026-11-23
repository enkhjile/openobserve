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

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("alerts", "execution_subject").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("alerts"))
                        .add_column(
                            ColumnDef::new(Alias::new("execution_subject"))
                                .text()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("alerts", "execution_subject").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Alias::new("alerts"))
                        .drop_column(Alias::new("execution_subject"))
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database};

    use super::*;

    #[tokio::test]
    async fn legacy_alerts_have_no_execution_identity() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        db.execute_unprepared("CREATE TABLE alerts (id TEXT PRIMARY KEY)")
            .await
            .unwrap();
        db.execute_unprepared("INSERT INTO alerts (id) VALUES ('legacy')")
            .await
            .unwrap();
        let manager = SchemaManager::new(&db);
        Migration.up(&manager).await.unwrap();
        Migration.up(&manager).await.unwrap();
        let row = db
            .query_one(sea_orm::Statement::from_string(
                sea_orm::DbBackend::Sqlite,
                "SELECT execution_subject FROM alerts WHERE id = 'legacy'",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.try_get::<Option<String>>("", "execution_subject")
                .unwrap(),
            None
        );
        Migration.down(&manager).await.unwrap();
        assert!(
            !manager
                .has_column("alerts", "execution_subject")
                .await
                .unwrap()
        );
    }
}
