//! Synthetic file format generators (.env, YAML, JSON, text) with exact span labels.

use rand::Rng;

use crate::generators::*;

/// Generates a realistic synthetic `.env` file with both sensitive and safe values.
pub fn gen_env_file<R: Rng>(rng: &mut R) -> SyntheticSample {
    let mut text = String::new();
    let mut labels = Vec::new();

    // Benign headers
    text.push_str("# Application Environment Variables\n");
    text.push_str("PORT=8080\n");
    text.push_str("NODE_ENV=production\n");
    text.push_str("LOG_LEVEL=info\n\n");

    // AWS Access Key
    let aws_key = gen_aws_access_key(rng);
    text.push_str("AWS_ACCESS_KEY_ID=");
    let start = text.len();
    text.push_str(&aws_key);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "aws_access_key".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push('\n');

    // AWS Secret Key
    let aws_sec = gen_aws_secret_key(rng);
    text.push_str("AWS_SECRET_ACCESS_KEY=");
    let start = text.len();
    text.push_str(&aws_sec);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "aws_secret_key".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push('\n');

    // Stripe Token
    let stripe_key = gen_stripe_token(rng);
    text.push_str("STRIPE_API_KEY=");
    let start = text.len();
    text.push_str(&stripe_key);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "stripe_key".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push('\n');

    // Database Connection String
    let db_url = gen_connection_string(rng);
    text.push_str("DATABASE_URL=\"");
    let start = text.len();
    text.push_str(&db_url);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "connection_string".to_string(),
        category: "ConnectionString".to_string(),
    });
    text.push_str("\"\n\n");

    // Negative safe UUID
    let uuid = gen_negative_sample(rng);
    text.push_str(&format!("INSTANCE_UUID={uuid}\n"));

    SyntheticSample { text, labels }
}

/// Generates a realistic synthetic YAML configuration file.
pub fn gen_yaml_file<R: Rng>(rng: &mut R) -> SyntheticSample {
    let mut text = String::new();
    let mut labels = Vec::new();

    text.push_str("service:\n");
    text.push_str("  name: core-billing-engine\n");
    text.push_str("  port: 8080\n");
    text.push_str("credentials:\n");

    let github_token = gen_github_token(rng);
    text.push_str("  github_token: \"");
    let start = text.len();
    text.push_str(&github_token);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "github_token".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push_str("\"\n");

    let openai_token = gen_openai_token(rng);
    text.push_str("  openai_api_key: \"");
    let start = text.len();
    text.push_str(&openai_token);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "openai_token".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push_str("\"\n");

    SyntheticSample { text, labels }
}

/// Generates a realistic synthetic JSON document.
pub fn gen_json_file<R: Rng>(rng: &mut R) -> SyntheticSample {
    let mut text = String::new();
    let mut labels = Vec::new();

    text.push_str("{\n");
    text.push_str("  \"organization\": \"Acme Corp\",\n");

    let anthropic = gen_anthropic_token(rng);
    text.push_str("  \"anthropic_key\": \"");
    let start = text.len();
    text.push_str(&anthropic);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "anthropic_token".to_string(),
        category: "KnownSecret".to_string(),
    });
    text.push_str("\",\n");

    let pan = gen_pan(rng);
    text.push_str("  \"pan_number\": \"");
    let start = text.len();
    text.push_str(&pan);
    let end = text.len();
    labels.push(SpanLabel {
        start,
        end,
        kind: "pan".to_string(),
        category: "IndianId".to_string(),
    });
    text.push_str("\"\n");

    text.push_str("}\n");

    SyntheticSample { text, labels }
}
