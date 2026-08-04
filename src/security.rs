use std::collections::HashMap;
use std::io::{self, Write};
use std::process::Command;

use anyhow::{bail, Context, Result};
use aur_security_checker::{
    check_repository, lookup, LookupCommitResult, LookupPackage as LookupWirePackage,
    LookupRequest, Provider, Verdict as LocalVerdict,
};
use futures::{stream, StreamExt};
use tr::tr;

use crate::config::Config;
use crate::download::Bases;
use crate::exec;

#[derive(Debug, Eq, PartialEq)]
pub enum SecurityDecision {
    Continue(SecurityReport),
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecurityStatus {
    Safe,
    PartialSafe,
    Suspicious,
    Dangerous,
    Unreviewed,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct SecurityReport {
    statuses: HashMap<String, SecurityStatus>,
}

impl SecurityReport {
    pub fn status(&self, package_base: &str) -> Option<SecurityStatus> {
        self.statuses.get(package_base).copied()
    }

    pub fn is_safe(&self, package_base: &str) -> bool {
        self.status(package_base) == Some(SecurityStatus::Safe)
    }

    fn unreviewed(bases: &Bases) -> Self {
        Self {
            statuses: bases
                .bases
                .iter()
                .map(|base| (base.package_base().to_string(), SecurityStatus::Unreviewed))
                .collect(),
        }
    }

    fn apply(&mut self, results: &[PackageResult]) {
        for result in results {
            let status = result.status();
            self.statuses.insert(result.package_base.clone(), status);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LookupPackage {
    package_base: String,
    directory: std::path::PathBuf,
    commits: Vec<String>,
    version: String,
    head: String,
    upstream_head: String,
    baseline: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    Safe,
    Suspicious,
    Dangerous,
}

#[derive(Clone, Debug)]
struct Assessment {
    verdict: Verdict,
    explanation: Option<String>,
}

#[derive(Debug)]
struct PackageResult {
    package_base: String,
    commit: String,
    version: String,
    commit_count: usize,
    covered: usize,
    remote_covered: usize,
    target_covered: bool,
    assessment: Option<Assessment>,
    remote_assessment: Option<Assessment>,
    local_assessment: Option<Assessment>,
    error: Option<anyhow::Error>,
}

impl PackageResult {
    fn status(&self) -> SecurityStatus {
        match self
            .assessment
            .as_ref()
            .map(|assessment| assessment.verdict)
        {
            Some(Verdict::Dangerous) => SecurityStatus::Dangerous,
            Some(Verdict::Suspicious) => SecurityStatus::Suspicious,
            Some(Verdict::Safe) if self.covered == self.commit_count && self.target_covered => {
                SecurityStatus::Safe
            }
            Some(Verdict::Safe) => SecurityStatus::PartialSafe,
            _ => SecurityStatus::Unreviewed,
        }
    }
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
        return Ok(SecurityDecision::Continue(SecurityReport::default()));
    }

    let local = match local_config(config) {
        Ok(local) => local,
        Err(error) => {
            print_local_warning(config, &error);
            if !config.aur_security_remote {
                return Ok(SecurityDecision::Continue(SecurityReport::default()));
            }
            None
        }
    };
    if !config.aur_security_remote && local.is_none() {
        print_configuration_help(config);
        return Ok(SecurityDecision::Continue(SecurityReport::default()));
    }

    let mut report = SecurityReport::unreviewed(bases);

    let mut packages = Vec::with_capacity(bases.bases.len());
    let mut unavailable = Vec::new();
    for base in &bases.bases {
        let package_base = base.package_base();
        match lookup_package(config, package_base, base.version()) {
            Ok(package) => packages.push(package),
            Err(error) => unavailable.push(Unavailable {
                package_base: package_base.to_string(),
                error,
            }),
        }
    }

    let mut results = if config.aur_security_remote {
        match lookup_remote(config, &packages).await {
            Ok(results) => results,
            Err(error) => {
                print_remote_warning(config, &error);
                unreviewed_results(&packages)
            }
        }
    } else {
        unreviewed_results(&packages)
    };

    if config.aur_security_remote {
        print_remote_report(config, &results);
    }

    if let Some(local) = local {
        let pending = packages
            .iter()
            .enumerate()
            .filter(|(index, _package)| {
                results[*index].covered < results[*index].commit_count
                    || !results[*index].target_covered
            })
            .map(|(index, package)| (index, package.clone()))
            .collect::<Vec<_>>();
        if !pending.is_empty() {
            print_local_start(config, pending.len(), local);
        }
        let assessments = pending
            .into_iter()
            .map(|(index, package)| async move { (index, assess_locally(local, &package).await) });
        let mut assessments =
            stream::iter(assessments).buffer_unordered(local_assessment_parallelism(config));
        while let Some((index, assessment)) = assessments.next().await {
            match assessment {
                Ok(assessment) => {
                    let result = &mut results[index];
                    result.covered = result.commit_count;
                    result.target_covered = true;
                    result.local_assessment = Some(assessment.clone());
                    merge_assessment(&mut result.assessment, assessment, false);
                }
                Err(error) => results[index].error = Some(error),
            }
        }
    }

    print_report(config, &results, local);
    for item in &unavailable {
        print_unavailable(config, item);
    }

    report.apply(&results);
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

    Ok(SecurityDecision::Continue(report))
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
        "claude" => Ok(Provider::Claude),
        "codex" => Ok(Provider::Codex),
        _ => bail!(tr!(
            "unknown AUR security provider '{}'; expected openai, anthropic, openrouter, claude, or codex",
            value
        )),
    }
}

fn lookup_package(config: &Config, package_base: &str, version: String) -> Result<LookupPackage> {
    let directory = config.fetch.clone_dir.join(package_base);
    let head = git_commit(config, &directory, package_base, "HEAD")?;
    let upstream_head = git_commit(config, &directory, package_base, "HEAD@{u}")?;
    let baseline = optional_git_commit(config, &directory, package_base, "AUR_SEEN")?;
    let mut commits = match &baseline {
        Some(_) => git_commits(
            config,
            &directory,
            package_base,
            &["rev-list", "--reverse", "AUR_SEEN..HEAD@{u}"],
        )?,
        None => Vec::new(),
    };
    if commits.is_empty() {
        commits.push(upstream_head.clone());
    }

    Ok(LookupPackage {
        package_base: package_base.to_string(),
        directory,
        commits,
        version,
        head,
        upstream_head,
        baseline,
    })
}

fn git_commit(
    config: &Config,
    directory: &std::path::Path,
    package_base: &str,
    revision: &str,
) -> Result<String> {
    let output = exec::command_output(
        Command::new(&config.git_bin)
            .args(&config.git_flags)
            .args(["rev-parse", "--verify", &format!("{revision}^{{commit}}")])
            .current_dir(directory),
    )?;
    parse_commit(package_base, &output.stdout)
}

fn optional_git_commit(
    config: &Config,
    directory: &std::path::Path,
    package_base: &str,
    revision: &str,
) -> Result<Option<String>> {
    let output = Command::new(&config.git_bin)
        .args(&config.git_flags)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{revision}^{{commit}}"),
        ])
        .current_dir(directory)
        .output()
        .with_context(|| tr!("failed to run git for '{}'", package_base))?;
    if output.status.success() {
        return parse_commit(package_base, &output.stdout).map(Some);
    }
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    bail!("{}", String::from_utf8_lossy(&output.stderr).trim())
}

fn git_commits(
    config: &Config,
    directory: &std::path::Path,
    package_base: &str,
    args: &[&str],
) -> Result<Vec<String>> {
    let output = exec::command_output(
        Command::new(&config.git_bin)
            .args(&config.git_flags)
            .args(args)
            .current_dir(directory),
    )?;
    String::from_utf8(output.stdout)
        .context(tr!("git returned non-UTF-8 commits for '{}'", package_base))?
        .lines()
        .map(|commit| validate_commit(package_base, commit))
        .collect()
}

fn parse_commit(package_base: &str, output: &[u8]) -> Result<String> {
    let commit = String::from_utf8(output.to_vec()).context(tr!(
        "git returned a non-UTF-8 commit for '{}'",
        package_base
    ))?;
    validate_commit(package_base, commit.trim())
}

fn validate_commit(package_base: &str, commit: &str) -> Result<String> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!(tr!(
            "git returned an invalid commit for '{}': {}",
            package_base,
            commit
        ));
    }
    Ok(commit.to_ascii_lowercase())
}

async fn lookup_remote(config: &Config, packages: &[LookupPackage]) -> Result<Vec<PackageResult>> {
    let response = lookup(
        config.aur_security_remote_url.as_str(),
        &LookupRequest {
            packages: packages
                .iter()
                .map(|package| LookupWirePackage {
                    package_base: package.package_base.clone(),
                    commits: package.commits.clone(),
                })
                .collect(),
        },
    )
    .await
    .context(tr!("could not fetch remote AUR security assessments"))?;

    response
        .results
        .into_iter()
        .zip(packages)
        .map(|(result, package)| remote_result(package, result.commits))
        .collect()
}

fn remote_result(
    package: &LookupPackage,
    commits: Vec<LookupCommitResult>,
) -> Result<PackageResult> {
    let mut result = unreviewed_result(package);
    for commit in commits {
        if let Some(assessment) = commit.assessment {
            let verdict = match assessment.verdict.as_str() {
                "safe" => Verdict::Safe,
                "suspicious" => Verdict::Suspicious,
                "dangerous" => Verdict::Dangerous,
                verdict => bail!(tr!("the AUR security API returned an unknown verdict '{}'; expected safe, suspicious, or dangerous", verdict)),
            };
            result.covered += 1;
            result.remote_covered += 1;
            let assessment = Assessment {
                verdict,
                explanation: assessment.explanation,
            };
            merge_assessment(&mut result.remote_assessment, assessment.clone(), true);
            merge_assessment(&mut result.assessment, assessment, true);
        }
    }
    Ok(result)
}

fn unreviewed_results(packages: &[LookupPackage]) -> Vec<PackageResult> {
    packages.iter().map(unreviewed_result).collect()
}

fn unreviewed_result(package: &LookupPackage) -> PackageResult {
    PackageResult {
        package_base: package.package_base.clone(),
        commit: package.head.clone(),
        version: package.version.clone(),
        commit_count: package.commits.len(),
        covered: 0,
        remote_covered: 0,
        target_covered: package.head == package.upstream_head,
        assessment: None,
        remote_assessment: None,
        local_assessment: None,
        error: None,
    }
}

async fn assess_locally(local: LocalConfig<'_>, package: &LookupPackage) -> Result<Assessment> {
    let checked = check_repository(
        local.provider,
        local.model,
        &package.package_base,
        &package.directory,
        package.baseline.as_deref(),
    )
    .await
    .with_context(|| {
        tr!(
            "failed to assess AUR package base '{}'",
            package.package_base
        )
    })?;

    if !package.head.eq_ignore_ascii_case(&checked.commit_id) {
        bail!(tr!(
            "the checker assessed commit {} for '{}', but paru downloaded {}",
            checked.commit_id,
            package.package_base,
            package.head
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
    })
}

fn merge_assessment(current: &mut Option<Assessment>, next: Assessment, replace_equal: bool) {
    let replace = current.as_ref().is_none_or(|current| {
        verdict_rank(next.verdict) > verdict_rank(current.verdict)
            || (replace_equal && verdict_rank(next.verdict) == verdict_rank(current.verdict))
    });
    if replace {
        *current = Some(next);
    }
}

fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Safe => 0,
        Verdict::Suspicious => 2,
        Verdict::Dangerous => 3,
    }
}

fn has_dangerous_assessment(results: &[PackageResult]) -> bool {
    results
        .iter()
        .any(|result| result.status() == SecurityStatus::Dangerous)
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

fn print_report(config: &Config, results: &[PackageResult], local: Option<LocalConfig<'_>>) {
    if results
        .iter()
        .any(|result| result.local_assessment.is_some() || result.error.is_some())
    {
        let heading = local.map_or_else(
            || tr!("Local AUR security assessments"),
            |local| {
                tr!(
                    "Local AUR security assessments from {}/{}",
                    clean(local.provider.as_str()),
                    clean(local.model)
                )
            },
        );
        print_report_header(config, heading);
        for result in results {
            if let Some(assessment) = &result.local_assessment {
                print_assessment_result(
                    config,
                    result,
                    assessment,
                    result.commit_count,
                    result.commit_count,
                );
            }
            if let Some(error) = &result.error {
                println!("    {}: {}", clean(&result.package_base), error);
            }
        }
    }

    for result in results {
        if result.assessment.is_none() {
            print_unreviewed_result(config, result);
        }
    }
}

fn print_remote_report(config: &Config, results: &[PackageResult]) {
    print_report_header(config, tr!("Remote AUR security assessments"));
    let mut results = results
        .iter()
        .filter(|result| result.remote_assessment.is_some())
        .collect::<Vec<_>>();
    results.sort_by_key(
        |result| match result.remote_assessment.as_ref().unwrap().verdict {
            Verdict::Safe if result.remote_covered == result.commit_count => 0,
            Verdict::Safe => 1,
            Verdict::Suspicious => 2,
            Verdict::Dangerous => 3,
        },
    );
    for result in results {
        let assessment = result.remote_assessment.as_ref().unwrap();
        print_assessment_result(
            config,
            result,
            assessment,
            result.remote_covered,
            result.commit_count,
        );
    }
}

fn print_report_header(config: &Config, heading: String) {
    let c = config.color;
    println!(
        "{} {}:",
        c.action.paint("::"),
        c.bold.paint(clean(&heading))
    );
    flush_stdout();
}

fn print_assessment_result(
    config: &Config,
    result: &PackageResult,
    assessment: &Assessment,
    covered: usize,
    total: usize,
) {
    let c = config.color;
    let verdict = match (assessment.verdict, covered != total) {
        (Verdict::Safe, true) => c.warning.paint(tr!("partial safe")),
        (Verdict::Safe, false) => c.upgrade.paint(tr!("safe")),
        (Verdict::Suspicious, _) => c.warning.paint(tr!("suspicious")),
        (Verdict::Dangerous, _) => c.error.paint(tr!("dangerous")),
    };
    let suffix = format!(" ({})", tr!("{} of {} commits assessed", covered, total));
    println!(
        "    {} {} {}  {}{}",
        c.bold.paint(clean(&result.package_base)),
        clean(&result.version),
        &result.commit[..7],
        verdict,
        suffix
    );
    if let Some(explanation) = &assessment.explanation {
        println!("        {}", indent(&clean(explanation)));
    }
    flush_stdout();
}

fn print_unreviewed_result(config: &Config, result: &PackageResult) {
    let c = config.color;
    let reason = if result.target_covered {
        partial_coverage_text(result.covered, result.commit_count)
            .expect("unreviewed upstream range must have partial coverage")
    } else {
        tr!("saved changes require local or manual review")
    };
    println!(
        "    {} {} {}  {} ({})",
        c.bold.paint(clean(&result.package_base)),
        clean(&result.version),
        &result.commit[..7],
        c.warning.paint(tr!("unreviewed")),
        reason
    );
    flush_stdout();
}

fn partial_coverage_text(covered: usize, total: usize) -> Option<String> {
    (covered != total).then(|| tr!("{} of {} commits assessed", covered, total))
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
    use std::fs;

    use super::*;

    fn assessment(verdict: Verdict) -> Assessment {
        Assessment {
            verdict,
            explanation: None,
        }
    }

    fn result(verdict: Option<Verdict>, covered: usize, commit_count: usize) -> PackageResult {
        PackageResult {
            package_base: "paru".to_string(),
            commit: "0123456789abcdef0123456789abcdef01234567".to_string(),
            version: "2.1.0-1".to_string(),
            commit_count,
            covered,
            remote_covered: covered,
            target_covered: true,
            assessment: verdict.map(assessment),
            remote_assessment: None,
            local_assessment: None,
            error: None,
        }
    }

    #[test]
    fn parses_supported_providers_case_insensitively() {
        assert_eq!(parse_provider("OpenAI").unwrap().as_str(), "openai");
        assert_eq!(parse_provider("anthropic").unwrap().as_str(), "anthropic");
        assert_eq!(parse_provider("openrouter").unwrap().as_str(), "openrouter");
        assert_eq!(parse_provider("Claude").unwrap().as_str(), "claude");
        assert_eq!(parse_provider("codex").unwrap().as_str(), "codex");
        assert!(parse_provider("unknown").is_err());
    }

    #[test]
    fn strips_terminal_control_characters() {
        assert_eq!(clean("safe\u{1b}[31m\nnext"), "safe[31m\nnext");
    }

    #[test]
    fn classifies_safe_and_dangerous_results() {
        assert_eq!(
            result(Some(Verdict::Safe), 2, 2).status(),
            SecurityStatus::Safe
        );
        assert_eq!(
            result(Some(Verdict::Safe), 1, 2).status(),
            SecurityStatus::PartialSafe
        );
        assert!(!has_dangerous_assessment(&[result(None, 0, 1)]));
        assert!(has_dangerous_assessment(&[result(
            Some(Verdict::Dangerous),
            1,
            2
        )]));
    }

    #[test]
    fn reports_each_assessment_status() {
        let mut report = SecurityReport::default();
        let mut suspicious = result(Some(Verdict::Suspicious), 1, 2);
        suspicious.package_base = "yay".to_string();
        report.apply(&[result(Some(Verdict::Safe), 2, 2), suspicious]);

        assert_eq!(report.status("paru"), Some(SecurityStatus::Safe));
        assert_eq!(report.status("yay"), Some(SecurityStatus::Suspicious));
        assert!(report.is_safe("paru"));
        assert_eq!(report.status("missing"), None);
    }

    #[test]
    fn local_range_coverage_does_not_mask_remote_risk() {
        let mut result = result(Some(Verdict::Suspicious), 1, 2);
        merge_assessment(&mut result.assessment, assessment(Verdict::Safe), false);
        result.covered = result.commit_count;
        assert_eq!(result.status(), SecurityStatus::Suspicious);
    }

    #[test]
    fn only_describes_partial_commit_coverage() {
        assert_eq!(partial_coverage_text(1, 1), None);
        assert_eq!(partial_coverage_text(3, 3), None);
        assert_eq!(
            partial_coverage_text(2, 3).as_deref(),
            Some("2 of 3 commits assessed")
        );
    }

    #[test]
    fn collects_every_upstream_commit_after_aur_seen() {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("paru");
        fs::create_dir(&repository).unwrap();
        git(&repository, &["init", "-b", "master"]);
        git(&repository, &["config", "user.name", "Test"]);
        git(&repository, &["config", "user.email", "test@example.com"]);

        fs::write(repository.join("PKGBUILD"), "pkgver=1\n").unwrap();
        git(&repository, &["add", "PKGBUILD"]);
        git(&repository, &["commit", "-m", "initial"]);
        git(&repository, &["update-ref", "AUR_SEEN", "HEAD"]);

        fs::write(repository.join("PKGBUILD"), "pkgver=2\n").unwrap();
        git(&repository, &["commit", "-am", "second"]);
        let second = git_output(&repository, &["rev-parse", "HEAD"]);
        fs::write(repository.join("PKGBUILD"), "pkgver=3\n").unwrap();
        git(&repository, &["commit", "-am", "third"]);
        let third = git_output(&repository, &["rev-parse", "HEAD"]);

        git(
            &repository,
            &["update-ref", "refs/remotes/origin/master", "HEAD"],
        );
        git(
            &repository,
            &[
                "config",
                "remote.origin.url",
                "https://example.invalid/paru.git",
            ],
        );
        git(
            &repository,
            &[
                "config",
                "remote.origin.fetch",
                "+refs/heads/*:refs/remotes/origin/*",
            ],
        );
        git(&repository, &["config", "branch.master.remote", "origin"]);
        git(
            &repository,
            &["config", "branch.master.merge", "refs/heads/master"],
        );

        let mut config = Config::default();
        config.git_bin = "git".to_string();
        config.fetch.clone_dir = directory.path().to_path_buf();
        let package = lookup_package(&config, "paru", "3-1".to_string()).unwrap();
        assert_eq!(package.commits, vec![second, third]);
        assert!(package.baseline.is_some());

        git(&repository, &["update-ref", "-d", "AUR_SEEN"]);
        let package = lookup_package(&config, "paru", "3-1".to_string()).unwrap();
        assert_eq!(package.commits, vec![package.upstream_head.clone()]);
        assert!(package.baseline.is_none());
    }

    fn git(directory: &std::path::Path, args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .current_dir(directory)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_output(directory: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(directory)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }
}
