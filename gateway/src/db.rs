//! PostgreSQL connection pool with migration support

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::{info, instrument};

/// Database handle wrapping a SQLx pool
#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    #[instrument]
    pub async fn connect(database_url: &str, max_connections: u32) -> anyhow::Result<Self> {
        info!("Connecting to PostgreSQL...");

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(2)
            .acquire_timeout(Duration::from_secs(10))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1800))
            .test_before_acquire(true)
            .connect(database_url)
            .await?;

        // Verify connectivity
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&pool)
            .await?;

        info!("PostgreSQL connection pool ready");
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[instrument(skip(self))]
    pub async fn migrate(&self) -> anyhow::Result<()> {
        info!("Running database migrations...");
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        info!("Migrations complete");
        Ok(())
    }

    pub async fn health_check(&self) -> bool {
        sqlx::query("SELECT 1").fetch_one(self.pool()).await.is_ok()
    }

    pub async fn close(&self) {
        info!("Closing database pool...");
        self.pool.close().await;
    }
}