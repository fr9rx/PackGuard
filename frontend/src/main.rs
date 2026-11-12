mod tui;

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
struct Options {
    mode: String,
    refs: Option<PathBuf>,
    benign: Option<PathBuf>,
    scan_dir: Option<PathBuf>,
    packages: Vec<PathBuf>,
    packguard: PathBuf,
    threads: usize,
    reports: Option<PathBuf>,
    stage2: bool,
    stage2_model: Option<PathBuf>,
    stage2_python: Option<PathBuf>,
    stage2_script: Option<PathBuf>,
    tui: bool,
}

#[derive(Clone)]
struct Report {
    package: String,
    version: String,
    score: Option<f64>,
    threshold: Option<f64>,
    flagged: bool,
    stage1_flagged: bool,
    stage2_prob: Option<f64>,
    stage2_flagged: Option<bool>,
    primitive_score: Option<u32>,
    primitive_flagged: bool,
    primitive_hits: String,
}

fn default_packguard() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("packguard.exe")
    } else {
        PathBuf::from("packguard")
    }
}

fn new_options() -> Options {
    Options {
        mode: "known".to_string(),
        refs: None,
        benign: None,
        scan_dir: None,
        packages: Vec::new(),
        packguard: default_packguard(),
        threads: 4,
        reports: None,
        stage2: false,
        stage2_model: None,
        stage2_python: None,
        stage2_script: None,
        tui: false,
    }
}

fn usage() {
    eprintln!(
        "usage: packguard-cli [--mode known|new] --refs <dir>\n\
         \x20                  (--scan-dir <dir> | --package <dir>...) [options]\n\
         \x20      packguard-cli --tui [--packguard <path>]\n\n\
         \x20 --mode      known (v6 views + benign veto) or new (raw NCD + primitives)\n\
         \x20 --refs      malware reference directory\n\
         \x20 --benign    benign reference directory (known mode: enables the benign veto)\n\
         \x20 --scan-dir  scan every package directly inside this directory\n\
         \x20 --package   scan one package directory; repeatable\n\
         \x20 --packguard path to the C scanner (default: packguard[.exe] from PATH)\n\
         \x20 --threads   worker threads (default 4)\n\
         \x20 --reports   keep reports in this directory instead of a temp directory\n\
         \x20 --stage2    pass the reports through the stage 2 ONNX model\n\
         \x20 --stage2-model  directory holding the ONNX model and tokenizer\n\
         \x20 --stage2-python Python interpreter for stage 2 (default: v2 venv, then\n\
         \x20                  python3 on POSIX and python on Windows)\n\
         \x20 --stage2-script stage2_filter.py (default: found next to this repo)\n\
         \x20 --tui       full-screen terminal interface (make menuconfig style)"
    );
}

fn parse_args() -> Result<Options, String> {
    let mut opts = new_options();
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                std::process::exit(0);
            }
            "--mode" => {
                opts.mode = args.next().ok_or("--mode needs known or new")?;
                if opts.mode != "known" && opts.mode != "new" {
                    return Err("--mode needs known or new".to_string());
                }
            }
            "--refs" => {
                opts.refs = Some(PathBuf::from(
                    args.next().ok_or("--refs needs a directory")?,
                ))
            }
            "--benign" => {
                opts.benign = Some(PathBuf::from(
                    args.next().ok_or("--benign needs a directory")?,
                ))
            }
            "--scan-dir" => {
                opts.scan_dir = Some(PathBuf::from(
                    args.next().ok_or("--scan-dir needs a directory")?,
                ))
            }
            "--package" => opts.packages.push(PathBuf::from(
                args.next().ok_or("--package needs a directory")?,
            )),
            "--packguard" => {
                opts.packguard = PathBuf::from(args.next().ok_or("--packguard needs a path")?)
            }
            "--threads" => {
                let value = args.next().ok_or("--threads needs a number")?;
                opts.threads = value
                    .parse::<usize>()
                    .map_err(|_| "--threads needs a number of 1 or more".to_string())?;
                if opts.threads == 0 {
                    return Err("--threads needs a number of 1 or more".to_string());
                }
            }
            "--reports" => {
                opts.reports = Some(PathBuf::from(
                    args.next().ok_or("--reports needs a directory")?,
                ))
            }
            "--stage2" => opts.stage2 = true,
            "--stage2-model" => {
                opts.stage2_model = Some(PathBuf::from(
                    args.next().ok_or("--stage2-model needs a directory")?,
                ))
            }
            "--stage2-python" => {
                opts.stage2_python = Some(PathBuf::from(
                    args.next().ok_or("--stage2-python needs a path")?,
                ))
            }
            "--stage2-script" => {
                opts.stage2_script = Some(PathBuf::from(
                    args.next().ok_or("--stage2-script needs a path")?,
                ))
            }
            "--tui" => opts.tui = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if !opts.stage2
        && (opts.stage2_model.is_some()
            || opts.stage2_python.is_some()
            || opts.stage2_script.is_some())
    {
        return Err(
            "--stage2-model, --stage2-python and --stage2-script need --stage2".to_string(),
        );
    }
    if !opts.tui {
        if opts.refs.is_none() {
            return Err("--refs is required (or use --tui)".to_string());
        }
        if opts.scan_dir.is_none() && opts.packages.is_empty() {
            return Err("--scan-dir or --package is required".to_string());
        }
    }
    Ok(opts)
}

fn target_paths(opts: &Options) -> Result<Vec<PathBuf>, String> {
    let mut targets = Vec::new();
    if let Some(dir) = &opts.scan_dir {
        let entries = fs::read_dir(dir)
            .map_err(|error| format!("cannot read --scan-dir {}: {error}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read --scan-dir: {error}"))?;
            let path = entry.path();
            let metadata = fs::metadata(&path)
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
            if metadata.is_dir() {
                targets.push(path);
            }
        }
    }
    targets.extend(opts.packages.iter().cloned());
    if targets.is_empty() {
        return Err("no packages found".to_string());
    }
    Ok(targets)
}

fn report_directory(opts: &Options) -> (PathBuf, bool) {
    if let Some(reports) = &opts.reports {
        return (reports.clone(), false);
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0);
    (
        env::temp_dir().join(format!("packguard-cli-{}-{}", std::process::id(), stamp)),
        true,
    )
}

fn default_stage2_script() -> Option<PathBuf> {
    let relative = PathBuf::from("stage 2 LLM Model")
        .join("v3")
        .join("stage2_filter.py");
    let mut roots = Vec::new();
    if let Ok(executable) = env::current_exe() {
        let mut current = executable.parent().map(|value| value.to_path_buf());
        while let Some(path) = current {
            roots.push(path.clone());
            current = path.parent().map(|value| value.to_path_buf());
        }
    }
    if let Ok(directory) = env::current_dir() {
        let mut current = Some(directory);
        while let Some(path) = current {
            roots.push(path.clone());
            current = path.parent().map(|value| value.to_path_buf());
        }
    }
    roots
        .into_iter()
        .map(|root| root.join(&relative))
        .find(|path| path.is_file())
}

fn stage2_script(opts: &Options) -> Result<PathBuf, String> {
    if let Some(script) = &opts.stage2_script {
        if !script.is_file() {
            return Err(format!("cannot find --stage2-script {}", script.display()));
        }
        return Ok(script.clone());
    }
    default_stage2_script()
        .ok_or_else(|| "cannot find stage2_filter.py; pass --stage2-script <path>".to_string())
}

fn stage2_model(opts: &Options, script: &Path) -> PathBuf {
    if let Some(model) = &opts.stage2_model {
        return model.clone();
    }
    script
        .parent()
        .map(|directory| directory.join("model_int8"))
        .unwrap_or_else(|| PathBuf::from("model_int8"))
}

fn stage2_python(opts: &Options, script: &Path) -> PathBuf {
    if let Some(python) = &opts.stage2_python {
        return python.clone();
    }
    if let Some(directory) = script.parent() {
        let venv = directory.join(".venv-stage2");
        for candidate in [
            venv.join("bin").join("python"),
            venv.join("Scripts").join("python.exe"),
        ] {
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    if cfg!(windows) {
        PathBuf::from("python")
    } else {
        PathBuf::from("python3")
    }
}

fn run_stage2(
    opts: &Options,
    reports_dir: &Path,
    progress: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let script = stage2_script(opts)?;
    let python = stage2_python(opts, &script);
    let model = stage2_model(opts, &script);
    if !model.is_dir() {
        return Err(format!(
            "stage 2 model directory {} does not exist; pass --stage2-model <dir> \
             or run stage 2 LLM Model/v2/install_model.sh",
            model.display()
        ));
    }

    progress(&format!(
        "Running stage 2 on the reports in {} with {} ...",
        reports_dir.display(),
        model.display()
    ));
    let output = Command::new(&python)
        .arg(&script)
        .arg("--reports")
        .arg(reports_dir)
        .arg("--out-dir")
        .arg(reports_dir)
        .arg("--model-dir")
        .arg(&model)
        .arg("--threads")
        .arg(opts.threads.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot run {}: {error}", python.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        let code = output.status.code().unwrap_or(-1);
        return Err(if detail.is_empty() {
            format!("stage 2 exited with {code}")
        } else {
            format!("stage 2 exited with {code}:\n{detail}")
        });
    }
    Ok(())
}

fn read_reports(reports_dir: &Path) -> Result<Vec<Report>, String> {
    let entries = fs::read_dir(reports_dir)
        .map_err(|error| format!("cannot read {}: {error}", reports_dir.display()))?;
    let mut reports = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&path) {
            if let Some(report) = parse_report(&text) {
                reports.push(report);
            }
        }
    }
    Ok(reports)
}

fn run_scan(opts: &Options, progress: &mut dyn FnMut(&str)) -> Result<Vec<Report>, String> {
    let refs = opts.refs.as_ref().ok_or("--refs is required")?;
    let targets = target_paths(opts)?;
    let (reports_dir, temporary) = report_directory(opts);
    if temporary {
        let _ = fs::remove_dir_all(&reports_dir);
    }
    fs::create_dir_all(&reports_dir)
        .map_err(|error| format!("cannot create {}: {error}", reports_dir.display()))?;
    if !temporary {
        if let Ok(entries) = fs::read_dir(&reports_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) == Some("json") {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    progress(&format!(
        "Scanning {} package(s) with mode {} ...",
        targets.len(),
        opts.mode
    ));
    let mut command = Command::new(&opts.packguard);
    command
        .arg("--mode")
        .arg(&opts.mode)
        .arg("-j")
        .arg(opts.threads.to_string())
        .arg("-p")
        .arg("256")
        .arg("-m")
        .arg("256");
    if let Some(benign) = &opts.benign {
        command.arg("-B").arg(benign);
    }
    let output = command
        .arg("-d")
        .arg(&reports_dir)
        .arg(refs)
        .args(&targets)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("cannot run {}: {error}", opts.packguard.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        if temporary {
            let _ = fs::remove_dir_all(&reports_dir);
        }
        return Err(format!(
            "packguard exited with {}:\n{}",
            output.status.code().unwrap_or(-1),
            detail
        ));
    }

    let stage1 = if opts.stage2 {
        match read_reports(&reports_dir) {
            Ok(reports) => Some(reports),
            Err(error) => {
                if temporary {
                    let _ = fs::remove_dir_all(&reports_dir);
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    if stage1.is_some() {
        if let Err(error) = run_stage2(opts, &reports_dir, progress) {
            if temporary {
                let _ = fs::remove_dir_all(&reports_dir);
            }
            return Err(error);
        }
    }
    let mut reports = match read_reports(&reports_dir) {
        Ok(reports) => reports,
        Err(error) => {
            if temporary {
                let _ = fs::remove_dir_all(&reports_dir);
            }
            return Err(error);
        }
    };
    if temporary {
        let _ = fs::remove_dir_all(&reports_dir);
    }
    if let Some(stage1) = &stage1 {
        for report in &mut reports {
            if let Some(previous) = stage1
                .iter()
                .find(|value| value.package == report.package && value.version == report.version)
            {
                report.stage1_flagged = previous.flagged;
            }
        }
    }
    if reports.is_empty() {
        return Err("packguard produced no reports".to_string());
    }
    reports.sort_by(|left, right| {
        right
            .flagged
            .cmp(&left.flagged)
            .then_with(|| {
                left.score
                    .unwrap_or(f64::INFINITY)
                    .partial_cmp(&right.score.unwrap_or(f64::INFINITY))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.package.cmp(&right.package))
    });
    Ok(reports)
}

fn field_start(json: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(position) = json[from..].find(&needle) {
        let after_key = from + position + needle.len();
        let rest = json[after_key..].trim_start();
        if let Some(after_colon) = rest.strip_prefix(':') {
            let value = after_colon.trim_start();
            return Some(json.len() - value.len());
        }
        from = after_key;
    }
    None
}

fn parse_string_after(json: &str, start: usize) -> Option<String> {
    let bytes = json.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut out = String::new();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Some(out),
            b'\\' => {
                index += 1;
                match bytes.get(index) {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{0008}'),
                    Some(b'f') => out.push('\u{000c}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        let hex = json.get(index + 1..index + 5)?;
                        let value = u32::from_str_radix(hex, 16).ok()?;
                        out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
                        index += 4;
                    }
                    _ => return None,
                }
                index += 1;
            }
            _ => {
                let ch = json[index..].chars().next()?;
                out.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    None
}

fn parse_number_after(json: &str, start: usize) -> Option<f64> {
    let rest = &json[start..];
    if rest.starts_with("null") {
        return None;
    }
    let end = rest
        .find(|ch: char| {
            !(ch.is_ascii_digit() || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E')
        })
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn parse_u32_after(json: &str, start: usize) -> Option<u32> {
    let rest = &json[start..];
    if rest.starts_with("null") {
        return None;
    }
    let end = rest
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn parse_bool_after(json: &str, start: usize) -> Option<bool> {
    let rest = &json[start..];
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn field_string(json: &str, key: &str) -> Option<String> {
    parse_string_after(json, field_start(json, key)?)
}

fn field_number(json: &str, key: &str) -> Option<f64> {
    parse_number_after(json, field_start(json, key)?)
}

fn field_u32(json: &str, key: &str) -> Option<u32> {
    parse_u32_after(json, field_start(json, key)?)
}

fn field_bool(json: &str, key: &str) -> Option<bool> {
    parse_bool_after(json, field_start(json, key)?)
}

fn parse_report(json: &str) -> Option<Report> {
    let flagged = field_bool(json, "flagged").unwrap_or(false);
    Some(Report {
        package: field_string(json, "package")?,
        version: field_string(json, "version").unwrap_or_default(),
        score: field_number(json, "score"),
        threshold: field_number(json, "threshold"),
        flagged,
        stage1_flagged: flagged,
        stage2_prob: field_number(json, "stage2_prob"),
        stage2_flagged: field_bool(json, "stage2_flagged"),
        primitive_score: field_u32(json, "primitive_score"),
        primitive_flagged: field_bool(json, "primitive_flagged").unwrap_or(false),
        primitive_hits: field_string(json, "primitive_hits").unwrap_or_default(),
    })
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('~');
    out
}

fn print_table(reports: &[Report], mode: &str, stage2: bool) {
    let threshold = reports
        .iter()
        .find_map(|report| report.threshold)
        .unwrap_or(0.50);
    println!(
        "\nMODE {mode}  threshold {threshold:.2}  packages {}",
        reports.len()
    );
    if stage2 {
        println!("Stage 2 filter on (probability column, - = not flagged by stage 1)");
    }
    println!(
        "{:<44} {:<16} {:>8} {:>5} {:>6} {:>7} HITS",
        "PACKAGE", "VERSION", "SCORE", "PRIM", "S2", "FLAGGED"
    );
    println!("{}", "-".repeat(108));
    for report in reports {
        let score = report
            .score
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "-".to_string());
        let primitive = match (report.primitive_score, report.primitive_flagged) {
            (Some(value), true) => format!("{value}*"),
            (Some(value), false) => value.to_string(),
            (None, _) => "-".to_string(),
        };
        let stage2_prob = match report.stage2_prob {
            Some(value) if report.stage1_flagged => format!("{value:.3}"),
            _ => "-".to_string(),
        };
        println!(
            "{:<44} {:<16} {:>8} {:>5} {:>6} {:>7} {}",
            truncate(&report.package, 44),
            truncate(&report.version, 16),
            score,
            primitive,
            stage2_prob,
            if report.flagged { "YES" } else { "no" },
            report.primitive_hits
        );
    }
    let flagged = reports.iter().filter(|report| report.flagged).count();
    println!(
        "\nFLAGGED {flagged}/{} ({:.1}%)   * = primitive rule fired",
        reports.len(),
        100.0 * flagged as f64 / reports.len() as f64
    );
    if stage2 {
        let stage1_flagged = reports
            .iter()
            .filter(|report| report.stage1_flagged)
            .count();
        let confirmed = reports
            .iter()
            .filter(|report| report.stage1_flagged && report.stage2_flagged == Some(true))
            .count();
        println!(
            "STAGE 1 flagged {stage1_flagged}/{}   STAGE 2 confirmed {confirmed}/{stage1_flagged}",
            reports.len()
        );
    }
}

fn main() {
    let opts = match parse_args() {
        Ok(opts) => opts,
        Err(error) => {
            eprintln!("packguard-cli: {error}");
            usage();
            std::process::exit(2);
        }
    };
    let result = if opts.tui {
        tui::run(opts)
    } else {
        run_scan(&opts, &mut |line| println!("{line}"))
            .map(|reports| print_table(&reports, &opts.mode, opts.stage2))
    };
    if let Err(error) = result {
        eprintln!("packguard-cli: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_fields() {
        let json = r#"{
            "package": "evil@1.0.0",
            "version": "1.0.0",
            "score": 0.42,
            "threshold": 0.50,
            "flagged": true,
            "primitive_score": 3,
            "primitive_flagged": true,
            "primitive_hits": "net host exec"
        }"#;
        let report = parse_report(json).unwrap();
        assert_eq!(report.package, "evil@1.0.0");
        assert_eq!(report.version, "1.0.0");
        assert_eq!(report.score, Some(0.42));
        assert_eq!(report.threshold, Some(0.50));
        assert!(report.flagged);
        assert_eq!(report.primitive_score, Some(3));
        assert!(report.primitive_flagged);
        assert_eq!(report.primitive_hits, "net host exec");
    }

    #[test]
    fn parses_null_score_and_missing_primitives() {
        let json = r#"{"package":"p","version":"","score":null,"threshold":0.5,"flagged":false}"#;
        let report = parse_report(json).unwrap();
        assert_eq!(report.score, None);
        assert!(!report.flagged);
        assert_eq!(report.primitive_score, None);
    }

    #[test]
    fn parses_stage2_fields() {
        let json = r#"{"package":"p","version":"1.0.0","score":0.4,"flagged":true,
            "stage2_prob":0.913,"stage2_flagged":false}"#;
        let report = parse_report(json).unwrap();
        assert_eq!(report.stage2_prob, Some(0.913));
        assert_eq!(report.stage2_flagged, Some(false));
        assert!(report.stage1_flagged);
    }

    #[test]
    fn stage2_fields_are_optional() {
        let json = r#"{"package":"p","version":"1","flagged":false}"#;
        let report = parse_report(json).unwrap();
        assert_eq!(report.stage2_prob, None);
        assert_eq!(report.stage2_flagged, None);
        assert!(!report.stage1_flagged);
    }

    #[test]
    fn parses_escaped_strings() {
        let json = r#"{"package":"a\"b\\c","version":"1"}"#;
        let report = parse_report(json).unwrap();
        assert_eq!(report.package, "a\"b\\c");
    }

    #[test]
    fn field_search_skips_nested_matches() {
        let json = r#"{"package":"top","nested":{"package":"inner"},"score":0.1}"#;
        assert_eq!(field_string(json, "package").as_deref(), Some("top"));
    }

    #[test]
    fn truncates_long_names() {
        assert_eq!(truncate("abcdefghij", 5), "abcd~");
        assert_eq!(truncate("abc", 5), "abc");
    }

    #[test]
    fn finds_stage2_script_next_to_the_repository() {
        let script = default_stage2_script().expect("stage2_filter.py should be found");
        assert!(script.ends_with(PathBuf::from("v2").join("stage2_filter.py")));
    }

    #[test]
    fn default_scanner_is_resolved_from_path() {
        let expected = if cfg!(windows) {
            PathBuf::from("packguard.exe")
        } else {
            PathBuf::from("packguard")
        };
        assert_eq!(default_packguard(), expected);
    }
}
