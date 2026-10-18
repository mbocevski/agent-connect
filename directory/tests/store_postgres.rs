//! Store conformance on Postgres (integration tier: `just test-int`, which
//! starts Postgres with docker compose and sets `AC_DIRECTORY_TEST_DB`).
//! Each store gets its own schema, dropped at the end of the run.

mod common;

use std::str::FromStr;

use agentconnect_directory::PgStore;
use sqlx::postgres::PgConnectOptions;

fn url() -> String {
    std::env::var("AC_DIRECTORY_TEST_DB").expect("AC_DIRECTORY_TEST_DB is set by just test-int")
}

async fn fresh() -> PgStore {
    let schema = format!(
        "t_{}",
        common::random_b64(9)
            .to_lowercase()
            .replace(['-', '_'], "x")
    );
    let admin = sqlx::PgPool::connect(&url()).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
        .execute(&admin)
        .await
        .unwrap();
    let opts = PgConnectOptions::from_str(&url())
        .unwrap()
        .options([("search_path", schema.as_str())]);
    PgStore::open_with(opts).await.unwrap()
}

#[tokio::test]
#[ignore = "needs Postgres: run with just test-int"]
async fn postgres_store_conforms() {
    common::store_suite::run(fresh).await;
}
