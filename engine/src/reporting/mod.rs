//! Markdown renderings of engine data. JSON output is plain `serde_json` on the data types.
//!
//! A value a receiver did not capture prints as `not captured`, never as a blank or 0.

use crate::fingerprint::{Baseline, Comparison, FieldStatus};

pub const NOT_CAPTURED: &str = "not captured";

/// Inline code safe inside a GFM table cell: `|` must be escaped even inside backticks.
fn cell(v: Option<&str>) -> String {
    format!("`{}`", v.unwrap_or(NOT_CAPTURED).replace('|', "\\|"))
}

/// The L1 comparison table (replaces scripts/fingerprint-analysis/summarize_l1.py).
pub fn baseline_table(baselines: &[Baseline]) -> String {
    let mut out = String::from("| client | http | ja4 | akamai_h2 | first_stream |\n|---|---|---|---|---|\n");
    for b in baselines {
        let f = &b.observation.fingerprint;
        let stream = f.http.h2_first_stream.map(|n| n.to_string());
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            cell(Some(&b.name)),
            cell(f.http.protocol.as_deref()),
            cell(f.tls.ja4.as_deref()),
            cell(f.http.akamai.as_deref()),
            cell(stream.as_deref()),
        ));
    }
    out.push_str("\n## Header order (pseudo-headers excluded) and User-Agent\n\n");
    for b in baselines {
        let f = &b.observation.fingerprint;
        let order = f.http.header_order.as_ref().map(|h| h.join(","));
        out.push_str(&format!(
            "- **{}**: `{}`  \n  UA: `{}`\n",
            b.name,
            order.as_deref().unwrap_or(NOT_CAPTURED),
            f.http.user_agent.as_deref().unwrap_or(NOT_CAPTURED),
        ));
    }
    out
}

/// One comparison as a table: differing fields first, then fields that could not be compared.
pub fn comparison_table(c: &Comparison) -> String {
    let mut out = format!(
        "**{}** vs **{}**: {} same, {} differ, {} not comparable\n\n| field | status | {} | {} |\n|---|---|---|---|\n",
        c.left, c.right, c.same, c.differs, c.not_comparable, c.left, c.right
    );
    let rank = |s: FieldStatus| match s {
        FieldStatus::Differs => 0,
        FieldStatus::OnlyLeft | FieldStatus::OnlyRight => 1,
        FieldStatus::Same => 2,
        FieldStatus::NeitherCaptured => 3,
    };
    let mut fields: Vec<_> = c.fields.iter().collect();
    fields.sort_by_key(|f| rank(f.status));
    for f in fields {
        let status = match f.status {
            FieldStatus::Same => "same",
            FieldStatus::Differs => "**differs**",
            FieldStatus::OnlyLeft => "only left captured",
            FieldStatus::OnlyRight => "only right captured",
            FieldStatus::NeitherCaptured => "neither captured",
        };
        out.push_str(&format!("| {} | {} | {} | {} |\n", f.field, status, cell(f.left.as_deref()), cell(f.right.as_deref())));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipes_are_escaped_and_blanks_say_not_captured() {
        assert_eq!(cell(Some("a|b")), "`a\\|b`");
        assert_eq!(cell(None), "`not captured`");
    }
}
