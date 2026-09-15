use sqlx::PgPool;

#[tokio::main]
async fn main() {
    let pool = PgPool::connect("postgres://...").await.unwrap();

    let user_id: i32 = 42;
    let user_email = "victim@example.com";

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND email = $2")
        .bind(user_id)
        .bind(user_email)
        .fetch_one(&pool)
        .await
        .expect("db query");

    let secret = "AKIAIOSFODNN7EXAMPLE";

    let row = sqlx::query(&format!("SELECT * FROM users WHERE id = {}", user_id))
        .fetch_one(&pool)
        .await
        .unwrap();

    let maybe_name: Option<&str> = None;
    let name = maybe_name.unwrap();
    println!("{}", name);
}
