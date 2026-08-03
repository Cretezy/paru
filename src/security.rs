use std::collections::HashSet;
use std::io::{self, Write};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aur_ai_security_checker::{check_package, Provider, Verdict as LocalVerdict};
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use tr::tr;
use url::Url;

use crate::config::Config;
use crate::download::Bases;
use crate::exec;

const LOOKUP_PATH: &str = "/api/v1/checks/lookup";
const MAX_LOOKUPS: usize = 1000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Eq, PartialEq)]
pub enum SecurityDecision {
    Continue(HashSet<String>),
    Abort,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct LookupPackage {
    package_base: String,
    commit: String,
    #[serde(skip)]
    version: String,
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
    assessment: Option<RemoteAssessment>,
}

#[derive(Debug, Deserialize)]
struct RemoteAssessment {
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

struct Assessment {
    verdict: Verdict,
    explanation: Option<String>,
    provider: String,
    model: String,
    version: String,
    details_path: Option<String>,
}

struct CheckResult {
    package_base: String,
    commit: String,
    assessment: Option<Assessment>,
}

struct Unavailable {
    package_base: String,
    error: anyhow::Error,
}

#[derive(Clone, Copy)]
struct LocalConfig<'a> {
    provider: Provider,
    model: &'a str,
}

pub async fn check(config: &Config, bases: &Bases) -> Result<SecurityDecision> {
    if config.skip_aur_security || bases.bases.is_empty() {
        return Ok(SecurityDecision::Continue(HashSet::new()));
    }

    let local = match local_config(config) {
        Ok(local) => local,
        Err(error) => {
            print_local_warning(config, &error);
            if !config.aur_security_remote {
                return Ok(SecurityDecision::Continue(HashSet::new()));
            }
            None
        }
    };
    if !config.aur_security_remote && local.is_none() {
        print_configuration_help(config);
        return Ok(SecurityDecision::Continue(HashSet::new()));
    }

    let mut packages = Vec::with_capacity(bases.bases.len());
    let mut unavailable = Vec::new();
    for base in &bases.bases {
        let package_base = base.package_base();
        match current_commit(config, package_base) {
            Ok(commit) => packages.push(LookupPackage {
                package_base: package_base.to_string(),
                commit,
                version: base.version(),
            }),
            Err(error) => unavailable.push(Unavailable {
                package_base: package_base.to_string(),
                error,
            }),
        }
    }

    let results = if config.aur_security_remote {
        match lookup_remote(config, &packages).await {
            Ok(results) => results,
            Err(error) => {
                print_remote_warning(config, &error);
                if local.is_none() {
                    return Ok(SecurityDecision::Continue(HashSet::new()));
                }
                unreviewed_results(&packages)
            }
        }
    } else {
        unreviewed_results(&packages)
    };

    let (mut results, pending): (Vec<_>, Vec<_>) = results
        .into_iter()
        .partition(|result| result.assessment.is_some());

    print_report_header(config);
    for result in &results {
        print_result(config, result);
    }

    if let Some(local) = local {
        if !pending.is_empty() {
            print_local_start(config, pending.len(), local);
        }
        let assessments = pending.into_iter().map(|result| {
            let package = packages
                .iter()
                .find(|package| package.package_base == result.package_base)
                .expect("lookup results were validated against requested packages");
            async move { (result, assess_locally(local, package).await) }
        });
        let mut assessments =
            stream::iter(assessments).buffer_unordered(local_assessment_parallelism(config));
        while let Some((mut result, assessment)) = assessments.next().await {
            match assessment {
                Ok(assessment) => {
                    result.assessment = Some(assessment);
                    print_result(config, &result);
                    results.push(result);
                }
                Err(error) => unavailable.push(Unavailable {
                    package_base: result.package_base,
                    error,
                }),
            }
        }
    } else {
        for result in pending {
            print_result(config, &result);
            results.push(result);
        }
    }

    for item in &unavailable {
        print_unavailable(config, item);
    }

    let safe_packages = safe_packages(&results);
    if config.no_confirm && has_dangerous_assessment(&results) {
        eprintln!(
            "{} {}",
            config.color.error.paint("::"),
            config.color.bold.paint(tr!(
                "aborting unattended installation due to a dangerous AUR security assessment"
            ))
        );
        return Ok(SecurityDecision::Abort);
    }

    Ok(SecurityDecision::Continue(safe_packages))
}

fn local_assessment_parallelism(config: &Config) -> usize {
    usize::try_from(config.pacman.parallel_downloads)
        .unwrap_or(usize::MAX)
        .max(1)
}

fn local_config(config: &Config) -> Result<Option<LocalConfig<'_>>> {
    match (
        config.aur_security_provider.as_deref(),
        config.aur_security_model.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(provider_name), Some(model)) if !provider_name.is_empty() && !model.is_empty() => {
            Ok(Some(LocalConfig {
                provider: parse_provider(provider_name)?,
                model,
            }))
        }
        _ => bail!(tr!(
            "both AurSecurityProvider and AurSecurityModel must be set for local assessments"
        )),
    }
}

fn parse_provider(value: &str) -> Result<Provider> {
    match value.to_ascii_lowercase().as_str() {
        "openai" => Ok(Provider::Openai),
        "anthropic" => Ok(Provider::Anthropic),
        "openrouter" => Ok(Provider::Openrouter),
        "codex" => Ok(Provider::Codex),
        _ => bail!(tr!(
            "unknown AUR security provider '{}'; expected openai, anthropic, openrouter, or codex",
            value
        )),
    }
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

async fn lookup_remote(config: &Config, packages: &[LookupPackage]) -> Result<Vec<CheckResult>> {
    let endpoint = config
        .aur_security_remote_url
        .join(LOOKUP_PATH)
        .context(tr!("invalid AUR security API URL"))?;
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!(
            "paru/{}",
            option_env!("PARU_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
        ))
        .build()
        .context(tr!("failed to create AUR security API client"))?;

    let mut results = Vec::with_capacity(packages.len());
    for chunk in packages.chunks(MAX_LOOKUPS) {
        results.extend(lookup(&client, &endpoint, chunk).await?);
    }
    Ok(results)
}

async fn lookup(
    client: &reqwest::Client,
    endpoint: &Url,
    packages: &[LookupPackage],
) -> Result<Vec<CheckResult>> {
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
    Ok(response
        .results
        .into_iter()
        .map(|result| CheckResult {
            package_base: result.package_base,
            commit: result.commit,
            assessment: result.assessment.map(|assessment| Assessment {
                verdict: assessment.verdict,
                explanation: assessment.explanation,
                provider: assessment.provider,
                model: assessment.model,
                version: assessment.version,
                details_path: Some(assessment.details_path),
            }),
        })
        .collect())
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

fn unreviewed_results(packages: &[LookupPackage]) -> Vec<CheckResult> {
    packages
        .iter()
        .map(|package| CheckResult {
            package_base: package.package_base.clone(),
            commit: package.commit.clone(),
            assessment: None,
        })
        .collect()
}

async fn assess_locally(local: LocalConfig<'_>, package: &LookupPackage) -> Result<Assessment> {
    let checked = check_package(
        local.provider,
        local.model,
        &package.package_base,
        &package.package_base,
    )
    .await
    .with_context(|| {
        tr!(
            "failed to assess AUR package base '{}'",
            package.package_base
        )
    })?;

    if !package.commit.eq_ignore_ascii_case(&checked.commit_id) {
        bail!(tr!(
            "the checker assessed commit {} for '{}', but paru downloaded {}",
            checked.commit_id,
            package.package_base,
            package.commit
        ));
    }

    let (verdict, explanation) = match checked.assessment.verdict {
        LocalVerdict::Safe => (Verdict::Safe, None),
        LocalVerdict::Suspicious(explanation) => (Verdict::Suspicious, Some(explanation)),
        LocalVerdict::Dangerous(explanation) => (Verdict::Dangerous, Some(explanation)),
    };
    Ok(Assessment {
        verdict,
        explanation,
        provider: local.provider.as_str().to_string(),
        model: local.model.to_string(),
        version: package.version.clone(),
        details_path: None,
    })
}

fn has_dangerous_assessment(results: &[CheckResult]) -> bool {
    results.iter().any(|result| {
        result
            .assessment
            .as_ref()
            .is_some_and(|assessment| assessment.verdict == Verdict::Dangerous)
    })
}

fn safe_packages(results: &[CheckResult]) -> HashSet<String> {
    results
        .iter()
        .filter(|result| {
            result
                .assessment
                .as_ref()
                .is_some_and(|assessment| assessment.verdict == Verdict::Safe)
        })
        .map(|result| result.package_base.clone())
        .collect()
}

fn print_remote_warning(config: &Config, error: &anyhow::Error) {
    eprintln!(
        "{} {}: {:#}",
        config.color.warning.paint("::"),
        config
            .color
            .bold
            .paint(tr!("could not obtain remote AUR security assessments")),
        error
    );
}

fn print_local_warning(config: &Config, error: &anyhow::Error) {
    eprintln!(
        "{} {}: {:#}",
        config.color.warning.paint("::"),
        config
            .color
            .bold
            .paint(tr!("could not run local AUR security assessments")),
        error
    );
}

fn print_configuration_help(config: &Config) {
    eprintln!(
        "{} {}",
        config.color.warning.paint("::"),
        config.color.bold.paint(tr!(
            "AUR security assessments are not configured; enable remote lookups or set both local settings in paru.conf:"
        ))
    );
    eprintln!("    AurSecurityRemote");
    eprintln!("    AurSecurityProvider = codex");
    eprintln!("    AurSecurityModel = <model>");
}

fn print_local_start(config: &Config, count: usize, local: LocalConfig<'_>) {
    let message = if count == 1 {
        tr!(
            "Starting 1 local AUR security assessment with {}/{}...",
            clean(local.provider.as_str()),
            clean(local.model)
        )
    } else {
        tr!(
            "Starting {} local AUR security assessments with {}/{}...",
            count,
            clean(local.provider.as_str()),
            clean(local.model)
        )
    };
    println!(
        "{} {}",
        config.color.action.paint("::"),
        config.color.bold.paint(message)
    );
    flush_stdout();
}

fn print_report_header(config: &Config) {
    let c = config.color;
    let heading = if config.aur_security_remote {
        tr!("Remote AUR security assessments:")
    } else {
        tr!("Local AUR security assessments:")
    };
    println!("{} {}", c.action.paint("::"), c.bold.paint(heading));
    flush_stdout();
}

fn print_result(config: &Config, result: &CheckResult) {
    let c = config.color;
    match &result.assessment {
        Some(assessment) => {
            let verdict = match assessment.verdict {
                Verdict::Safe => c.upgrade.paint(tr!("safe")),
                Verdict::Suspicious => c.warning.paint(tr!("suspicious")),
                Verdict::Dangerous => c.error.paint(tr!("dangerous")),
            };
            let source = assessment_source(&config.aur_security_remote_url, assessment);
            println!(
                "    {} {} {}  {} ({})",
                c.bold.paint(clean(&result.package_base)),
                clean(&assessment.version),
                &result.commit[..7],
                verdict,
                clean(&source)
            );
            if let Some(explanation) = &assessment.explanation {
                println!("        {}", indent(&clean(explanation)));
            }
        }
        None => println!(
            "    {} {}  {} ({})",
            c.bold.paint(clean(&result.package_base)),
            &result.commit[..7],
            c.warning.paint(tr!("unreviewed")),
            tr!("no assessment for this commit")
        ),
    }
    flush_stdout();
}

fn print_unavailable(config: &Config, item: &Unavailable) {
    let c = config.color;
    println!(
        "    {}  {} ({:#})",
        c.bold.paint(clean(&item.package_base)),
        c.warning.paint(tr!("unreviewed")),
        item.error
    );
    flush_stdout();
}

fn assessment_source(remote_url: &Url, assessment: &Assessment) -> String {
    assessment.details_path.as_ref().map_or_else(
        || {
            format!(
                "{}/{}",
                clean(&assessment.provider),
                clean(&assessment.model)
            )
        },
        |details_path| {
            remote_url
                .join(details_path)
                .map_or_else(|_| clean(details_path), |url| url.to_string())
        },
    )
}

fn flush_stdout() {
    let _ = io::stdout().flush();
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
            version: "2.1.0-1".to_string(),
        }
    }

    fn result(verdict: Option<Verdict>) -> CheckResult {
        CheckResult {
            package_base: "paru".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            assessment: verdict.map(|verdict| Assessment {
                verdict,
                explanation: None,
                provider: "codex".to_string(),
                model: "model".to_string(),
                version: "1-1".to_string(),
                details_path: None,
            }),
        }
    }

    #[test]
    fn displays_remote_url_or_local_provider_and_model_as_the_source() {
        let remote_url = Url::parse("https://security.example/base").unwrap();
        let mut assessment = result(Some(Verdict::Safe)).assessment.unwrap();
        assert_eq!(assessment_source(&remote_url, &assessment), "codex/model");

        assessment.details_path = Some("/checks/paru/commit".to_string());
        assert_eq!(
            assessment_source(&remote_url, &assessment),
            "https://security.example/checks/paru/commit"
        );
    }

    #[test]
    fn parses_supported_providers_case_insensitively() {
        assert_eq!(parse_provider("OpenAI").unwrap().as_str(), "openai");
        assert_eq!(parse_provider("anthropic").unwrap().as_str(), "anthropic");
        assert_eq!(parse_provider("openrouter").unwrap().as_str(), "openrouter");
        assert_eq!(parse_provider("codex").unwrap().as_str(), "codex");
        assert!(parse_provider("unknown").is_err());
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
    fn serializes_only_the_remote_api_fields() {
        let package = package("paru", "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(
            serde_json::to_value(&package).unwrap(),
            json!({ "package_base": "paru", "commit": package.commit })
        );
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
    fn classifies_safe_and_dangerous_results() {
        assert!(!has_dangerous_assessment(&[result(Some(Verdict::Safe))]));
        assert_eq!(
            safe_packages(&[result(Some(Verdict::Safe))]),
            HashSet::from(["paru".to_string()])
        );
        assert!(safe_packages(&[result(Some(Verdict::Suspicious))]).is_empty());
        assert!(!has_dangerous_assessment(&[result(None)]));
        assert!(has_dangerous_assessment(&[result(Some(
            Verdict::Dangerous
        ))]));
    }
}
