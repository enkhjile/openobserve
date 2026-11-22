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
use infra::table::entity::sessions::{ActiveModel, Column, Entity};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryTrait, Set, TransactionTrait,
    sea_query::{Expr, Query},
};

pub async fn start_transaction(marker: &str, expires_at: i64) -> Result<()> {
    Entity::insert(session_model(marker, "", expires_at))
        .exec(infra::db::get_orm_client_rw().await)
        .await?;
    Ok(())
}

/// Keep the marker on failure so a retried logout can revoke the issued session. [strong]
pub async fn revoke(markers: Vec<String>, current: Option<String>) -> Result<()> {
    let transaction = infra::db::get_orm_client_rw().await.begin().await?;
    // One DELETE ... RETURNING locks each marker and reads the session it issued.
    let mut stmt = Entity::delete_many()
        .filter(Column::SessionId.is_in(markers))
        .into_query();
    stmt.returning(Query::returning().column(Column::AccessToken));
    let rows = transaction
        .query_all(transaction.get_database_backend().build(&stmt))
        .await?;
    let mut issued = rows
        .iter()
        .map(|row| row.try_get::<String>("", "access_token"))
        .collect::<Result<Vec<_>, _>>()?;
    issued.retain(|session_id| !session_id.is_empty());
    issued.extend(current);
    if !issued.is_empty() {
        Entity::delete_many()
            .filter(Column::SessionId.is_in(issued))
            .exec(&transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

/// The previous session remains valid if storing the replacement fails. [strong]
pub async fn rotate(
    marker: &str,
    previous_id: Option<&str>,
    session_id: &str,
    access_token: &str,
    expires_at: i64,
) -> Result<()> {
    let transaction = infra::db::get_orm_client_rw().await.begin().await?;
    // Take the marker's write lock before touching session rows, in the same order as logout.
    let claimed = Entity::update_many()
        .col_expr(Column::AccessToken, Expr::value(session_id))
        .filter(Column::SessionId.eq(marker))
        .filter(Column::AccessToken.eq(""))
        .exec(&transaction)
        .await?;
    ensure!(
        claimed.rows_affected == 1,
        "OIDC login cancelled or already completed"
    );
    Entity::insert(session_model(session_id, access_token, expires_at))
        .exec(&transaction)
        .await?;
    if let Some(previous_id) = previous_id {
        Entity::delete_by_id(previous_id).exec(&transaction).await?;
    }
    // Check both deadlines after any wait for the writer, then keep the revocation handle as long
    // as the session.
    let now = config::utils::time::now_micros();
    let published = Entity::update_many()
        .col_expr(Column::ExpiresAt, Expr::value(expires_at))
        .filter(Column::SessionId.eq(marker))
        .filter(Column::ExpiresAt.gt(now))
        .exec(&transaction)
        .await?;
    ensure!(
        published.rows_affected == 1 && expires_at > now,
        "OIDC login expired"
    );
    transaction.commit().await?;
    Ok(())
}

fn session_model(session_id: &str, access_token: &str, expires_at: i64) -> ActiveModel {
    let now = config::utils::time::now_micros();
    ActiveModel {
        session_id: Set(session_id.to_string()),
        access_token: Set(access_token.to_string()),
        created_at: Set(now),
        updated_at: Set(now),
        expires_at: Set(expires_at),
    }
}
