use std::io::{self, Write};
use std::process::Command;

use anyhow::{bail, Context, Result};
use aur_ai_security_checker::{check_package, Assessment, Provider, Verdict};
use tr::tr;

use crate::config::Config;
use crate::download::Bases;
use crate::exec;
use crate::util::ask;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityDecision {
    Continue,
    Abort,
}

struct CheckResult {
    package_base: String,
    commit: String,
    version: String,
    assessment: Assessment,
}

struct Unavailable {
    package_base: String,
    error: anyhow::Error,
}

pub async fn check(config: &Config, bases: &Bases) -> Result<SecurityDecision> {
    if config.skip_aur_security || bases.bases.is_empty() {
        return Ok(SecurityDecision::Continue);
    }

    let (provider_name, model) = match (
        config.aur_security_provider.as_deref(),
        config.aur_security_model.as_deref(),
    ) {
        (Some(provider), Some(model)) if !provider.is_empty() && !model.is_empty() => {
            (provider, model)
        }
        _ => {
            print_configuration_help(config);
            return Ok(SecurityDecision::Continue);
        }
    };

    let provider = match parse_provider(provider_name) {
        Ok(provider) => provider,
        Err(error) => {
            print_checker_warning(config, &error);
            return Ok(SecurityDecision::Continue);
        }
    };

    print_assessment_start(config, bases.bases.len(), provider_name, model);
    print_report_header(config);

    let mut results = Vec::with_capacity(bases.bases.len());
    let mut unavailable = Vec::new();
    for base in &bases.bases {
        let package_base = base.package_base();
        let result = async {
            let expected_commit = current_commit(config, package_base)?;
            let checked = check_package(provider, model, package_base, package_base)
                .await
                .with_context(|| tr!("failed to assess AUR package base '{}'", package_base))?;

            if !expected_commit.eq_ignore_ascii_case(&checked.commit_id) {
                bail!(tr!(
                    "the checker assessed commit {} for '{}', but paru downloaded {}",
                    checked.commit_id,
                    package_base,
                    expected_commit
                ));
            }

            Ok(CheckResult {
                package_base: package_base.to_string(),
                commit: checked.commit_id,
                version: base.version(),
                assessment: checked.assessment,
            })
        }
        .await;

        match result {
            Ok(result) => {
                print_result(config, &result);
                results.push(result);
            }
            Err(error) => {
                let item = Unavailable {
                    package_base: package_base.to_string(),
                    error,
                };
                print_unavailable(config, &item);
                unavailable.push(item);
            }
        }
    }

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

fn risk_state(results: &[CheckResult], locally_unavailable: bool) -> (bool, bool) {
    let dangerous = results
        .iter()
        .any(|result| matches!(result.assessment.verdict, Verdict::Dangerous(_)));
    let has_risk = locally_unavailable
        || results
            .iter()
            .any(|result| !matches!(result.assessment.verdict, Verdict::Safe));
    (has_risk, dangerous)
}

fn print_checker_warning(config: &Config, error: &anyhow::Error) {
    eprintln!(
        "{} {}: {:#}",
        config.color.warning.paint("::"),
        config
            .color
            .bold
            .paint(tr!("could not run AUR security assessments")),
        error
    );
}

fn print_configuration_help(config: &Config) {
    eprintln!(
        "{} {}",
        config.color.warning.paint("::"),
        config.color.bold.paint(tr!(
            "AUR security assessments are not configured; set both of these in paru.conf:"
        ))
    );
    eprintln!("    AurSecurityProvider = codex");
    eprintln!("    AurSecurityModel = <model>");
    eprintln!(
        "    {}",
        tr!("supported providers: openai, anthropic, openrouter, codex")
    );
}

fn print_assessment_start(config: &Config, count: usize, provider: &str, model: &str) {
    let message = if count == 1 {
        tr!(
            "Starting 1 AUR security assessment with {}/{}...",
            clean(provider),
            clean(model)
        )
    } else {
        tr!(
            "Starting {} AUR security assessments with {}/{}...",
            count,
            clean(provider),
            clean(model)
        )
    };
    println!(
        "{} {}",
        config.color.action.paint("::"),
        config.color.bold.paint(message)
    );
}

fn print_report_header(config: &Config) {
    let c = config.color;
    println!(
        "{} {}",
        c.action.paint("::"),
        c.bold.paint(tr!("AUR security assessments:"))
    );
    flush_stdout();
}

fn print_result(config: &Config, result: &CheckResult) {
    let c = config.color;
    let (verdict, explanation) = match &result.assessment.verdict {
        Verdict::Safe => (c.upgrade.paint(tr!("safe")), None),
        Verdict::Suspicious(explanation) => (c.warning.paint(tr!("suspicious")), Some(explanation)),
        Verdict::Dangerous(explanation) => (c.error.paint(tr!("dangerous")), Some(explanation)),
    };
    println!(
        "    {} {} {} {}",
        c.bold.paint(clean(&result.package_base)),
        clean(&result.version),
        &result.commit[..7],
        verdict
    );
    if let Some(explanation) = explanation {
        println!("        {}", indent(&clean(explanation)));
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
    use super::*;

    fn result(verdict: Verdict) -> CheckResult {
        CheckResult {
            package_base: "paru".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            version: "2.1.0-1".to_string(),
            assessment: Assessment { verdict },
        }
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
    fn strips_terminal_control_characters() {
        assert_eq!(clean("safe\u{1b}[31m\nnext"), "safe[31m\nnext");
    }

    #[test]
    fn classifies_safe_suspicious_dangerous_and_unavailable_results() {
        assert_eq!(risk_state(&[result(Verdict::Safe)], false), (false, false));
        assert_eq!(
            risk_state(&[result(Verdict::Suspicious("review".to_string()))], false),
            (true, false)
        );
        assert_eq!(
            risk_state(&[result(Verdict::Dangerous("malware".to_string()))], false),
            (true, true)
        );
        assert_eq!(risk_state(&[result(Verdict::Safe)], true), (true, false));
    }
}
