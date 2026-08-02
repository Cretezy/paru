use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tr::tr;
use url::Url;

use crate::config::Config;
use crate::download::Bases;
use crate::exec;
use crate::util::ask;

const LOOKUP_PATH: &str = "/api/v1/checks/lookup";
const MAX_LOOKUPS: usize = 100;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityDecision {
    Continue,
    Abort,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct LookupPackage {
    package_base: String,
    commit: String,
}

#[derive(Serialize)]
struct LookupRequest<'a> {
    packages: &'a [LookupPackage],
}

#[derive(Debug, Deserialize)]
struct LookupResponse {
    results: Vec<LookupResult>,
}

#[derive(Debug, Deserialize)]
struct LookupResult {
    package_base: String,
    commit: String,
    assessment: Option<Assessment>,
}

#[derive(Debug, Deserialize)]
struct Assessment {
    verdict: Verdict,
    explanation: Option<String>,
    provider: String,
    model: String,
    #[serde(rename = "checked_at")]
    _checked_at: i64,
    version: String,
    details_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Verdict {
    Safe,
    Suspicious,
    Dangerous,
}

struct Unavailable {
    package_base: String,
    error: anyhow::Error,
}

pub async fn check(config: &Config, bases: &Bases) -> Result<SecurityDecision> {
    if config.skip_aur_security || bases.bases.is_empty() {
        return Ok(SecurityDecision::Continue);
    }

    let mut packages = Vec::with_capacity(bases.bases.len());
    let mut unavailable = Vec::new();
    for base in &bases.bases {
        let package_base = base.package_base();
        match current_commit(config, package_base) {
            Ok(commit) => packages.push(LookupPackage {
                package_base: package_base.to_string(),
                commit,
            }),
            Err(error) => unavailable.push(Unavailable {
                package_base: package_base.to_string(),
                error,
            }),
        }
    }

    let endpoint = match config
        .aur_security_url
        .join(LOOKUP_PATH)
        .context(tr!("invalid AUR security API URL"))
    {
        Ok(endpoint) => endpoint,
        Err(error) => {
            print_api_warning(config, &error);
            return Ok(SecurityDecision::Continue);
        }
    };
    let client = match reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!(
            "paru/{}",
            option_env!("PARU_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        ))
        .build()
        .context(tr!("failed to create AUR security API client"))
    {
        Ok(client) => client,
        Err(error) => {
            print_api_warning(config, &error);
            return Ok(SecurityDecision::Continue);
        }
    };

    let mut results = Vec::with_capacity(packages.len());
    for chunk in packages.chunks(MAX_LOOKUPS) {
        match lookup(&client, &endpoint, chunk).await {
            Ok(mut chunk_results) => results.append(&mut chunk_results),
            Err(error) => {
                print_api_warning(config, &error);
                return Ok(SecurityDecision::Continue);
            }
        }
    }

    print_report(config, &results, &unavailable);

    let (has_risk, dangerous) = risk_state(&results, !unavailable.is_empty());

    if config.no_confirm {
        if dangerous {
            eprintln!(
                "{} {}",
                config.color.error.paint("::"),
                config.color.bold.paint(tr!(
                    "aborting unattended installation due to a dangerous AUR security assessment"
                ))
            );
            return Ok(SecurityDecision::Abort);
        }
        return Ok(SecurityDecision::Continue);
    }

    if has_risk
        && !ask(
            config,
            &tr!("Proceed despite AUR security warnings?"),
            false,
        )
    {
        return Ok(SecurityDecision::Abort);
    }

    Ok(SecurityDecision::Continue)
}

fn current_commit(config: &Config, package_base: &str) -> Result<String> {
    let directory = config.fetch.clone_dir.join(package_base);
    let output = exec::command_output(
        Command::new(&config.git_bin)
            .args(["rev-parse", "HEAD"])
            .current_dir(&directory),
    )?;
    let commit = String::from_utf8(output.stdout).context(tr!(
        "git returned a non-UTF-8 commit for '{}'",
        package_base
    ))?;
    let commit = commit.trim();
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!(tr!(
            "git returned an invalid commit for '{}': {}",
            package_base,
            commit
        ));
    }
    Ok(commit.to_ascii_lowercase())
}

async fn lookup(
    client: &reqwest::Client,
    endpoint: &Url,
    packages: &[LookupPackage],
) -> Result<Vec<LookupResult>> {
    let response = client
        .post(endpoint.clone())
        .json(&LookupRequest { packages })
        .send()
        .await
        .context(tr!("failed to contact the AUR security API"))?
        .error_for_status()
        .context(tr!("the AUR security API returned an error"))?
        .json::<LookupResponse>()
        .await
        .context(tr!("the AUR security API returned invalid JSON"))?;

    validate_response(packages, &response.results)?;
    Ok(response.results)
}

fn validate_response(packages: &[LookupPackage], results: &[LookupResult]) -> Result<()> {
    if packages.len() != results.len() {
        bail!(tr!("the AUR security API returned an incomplete response"));
    }
    for (package, result) in packages.iter().zip(results) {
        if package.package_base != result.package_base
            || !package.commit.eq_ignore_ascii_case(&result.commit)
        {
            bail!(tr!("the AUR security API returned mismatched package data"));
        }
    }
    Ok(())
}

fn risk_state(results: &[LookupResult], locally_unavailable: bool) -> (bool, bool) {
    let dangerous = results.iter().any(|result| {
        result
            .assessment
            .as_ref()
            .is_some_and(|assessment| assessment.verdict == Verdict::Dangerous)
    });
    let has_risk = locally_unavailable
        || results.iter().any(|result| {
            result
                .assessment
                .as_ref()
                .is_none_or(|assessment| assessment.verdict != Verdict::Safe)
        });
    (has_risk, dangerous)
}

fn print_api_warning(config: &Config, error: &anyhow::Error) {
    eprintln!(
        "{} {}: {:#}",
        config.color.warning.paint("::"),
        config
            .color
            .bold
            .paint(tr!("could not obtain AUR security assessments")),
        error
    );
}

fn print_report(config: &Config, results: &[LookupResult], unavailable: &[Unavailable]) {
    let c = config.color;
    println!(
        "{} {}",
        c.action.paint("::"),
        c.bold.paint(tr!("AUR security assessments:"))
    );

    for result in results {
        match &result.assessment {
            Some(assessment) => {
                let verdict = match assessment.verdict {
                    Verdict::Safe => c.upgrade.paint(tr!("safe")),
                    Verdict::Suspicious => c.warning.paint(tr!("suspicious")),
                    Verdict::Dangerous => c.error.paint(tr!("dangerous")),
                };
                println!(
                    "    {} {}  {} ({}/{})",
                    c.bold.paint(clean(&result.package_base)),
                    clean(&assessment.version),
                    verdict,
                    clean(&assessment.provider),
                    clean(&assessment.model)
                );
                if let Some(explanation) = &assessment.explanation {
                    println!("        {}", indent(&clean(explanation)));
                }
                let details = config
                    .aur_security_url
                    .join(&assessment.details_path)
                    .map_or_else(|_| clean(&assessment.details_path), |url| url.to_string());
                println!("        {}", details);
            }
            None => println!(
                "    {} {}  {} ({})",
                c.bold.paint(clean(&result.package_base)),
                &result.commit[..7],
                c.warning.paint(tr!("unreviewed")),
                tr!("no assessment for this commit")
            ),
        }
    }

    for item in unavailable {
        println!(
            "    {}  {} ({:#})",
            c.bold.paint(clean(&item.package_base)),
            c.warning.paint(tr!("unreviewed")),
            item.error
        );
    }
}

fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|character| *character == '\n' || *character == '\t' || !character.is_control())
        .collect()
}

fn indent(value: &str) -> String {
    value.replace('\n', "\n        ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn package(package_base: &str, commit: &str) -> LookupPackage {
        LookupPackage {
            package_base: package_base.to_string(),
            commit: commit.to_string(),
        }
    }

    #[test]
    fn validates_ordered_exact_response() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let packages = vec![package("paru", commit)];
        let results = vec![LookupResult {
            package_base: "paru".to_string(),
            commit: commit.to_ascii_uppercase(),
            assessment: None,
        }];
        assert!(validate_response(&packages, &results).is_ok());
    }

    #[test]
    fn rejects_incomplete_or_mismatched_response() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let packages = vec![package("paru", commit)];
        assert!(validate_response(&packages, &[]).is_err());

        let results = vec![LookupResult {
            package_base: "yay".to_string(),
            commit: commit.to_string(),
            assessment: None,
        }];
        assert!(validate_response(&packages, &results).is_err());
    }

    #[test]
    fn strips_terminal_control_characters() {
        assert_eq!(clean("safe\u{1b}[31m\nnext"), "safe[31m\nnext");
    }

    #[test]
    fn decodes_the_public_api_contract() {
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let response: LookupResponse = serde_json::from_value(json!({
            "results": [{
                "package_base": "paru",
                "commit": commit,
                "assessment": {
                    "verdict": "suspicious",
                    "explanation": "changed upstream",
                    "provider": "codex",
                    "model": "gpt-test",
                    "checked_at": 42,
                    "version": "2.1.0-1",
                    "details_path": format!("/checks/paru/{commit}")
                }
            }]
        }))
        .expect("the API response should decode");

        let assessment = response.results[0]
            .assessment
            .as_ref()
            .expect("assessment should be present");
        assert_eq!(assessment.verdict, Verdict::Suspicious);
        assert_eq!(assessment.explanation.as_deref(), Some("changed upstream"));
    }

    #[test]
    fn classifies_safe_unreviewed_and_dangerous_results() {
        fn result(verdict: Option<Verdict>) -> LookupResult {
            LookupResult {
                package_base: "paru".to_string(),
                commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
                assessment: verdict.map(|verdict| Assessment {
                    verdict,
                    explanation: None,
                    provider: "codex".to_string(),
                    model: "model".to_string(),
                    _checked_at: 1,
                    version: "1-1".to_string(),
                    details_path: "/checks/paru/commit".to_string(),
                }),
            }
        }

        assert_eq!(
            risk_state(&[result(Some(Verdict::Safe))], false),
            (false, false)
        );
        assert_eq!(risk_state(&[result(None)], false), (true, false));
        assert_eq!(
            risk_state(&[result(Some(Verdict::Dangerous))], false),
            (true, true)
        );
        assert_eq!(
            risk_state(&[result(Some(Verdict::Safe))], true),
            (true, false)
        );
    }
}
