//! Converts a public NVIDIA OpenShell sandbox policy into a Guard policy and
//! reports every field it could not honour.
//!
//! The report is not a courtesy: a refused conversion prints its findings and
//! writes no policy, because a policy that looks equivalent to the source and is
//! strictly more permissive is worse than no conversion at all. Nothing this
//! tool prints comes from the source document except field paths and static
//! explanations, so an operator's terminal never receives guest-authored text.

use aiec_guard::openshell::{self, ImportFailure, ImportReport, SCHEMA_REFERENCE};
use clap::Parser;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::ExitCode,
};

/// Largest policy document read from disk, matching the source schema's limit.
const MAX_DOCUMENT_BYTES: u64 = openshell::MAX_IMPORT_BYTES as u64;

#[derive(Parser)]
#[command(
    name = "aiec-guard-import-openshell",
    about = "Convert an OpenShell policy to a Guard policy with a full unsupported-fields report"
)]
struct Args {
    /// OpenShell policy document to read.
    #[arg(long)]
    input: PathBuf,
    /// Where to write the converted Guard policy YAML.
    #[arg(long)]
    out: PathBuf,
    /// Where to write the converted layer 7 rules, when the source policy
    /// implies any. Not written when there are none.
    #[arg(long)]
    l7_out: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = args.out.display().to_string();
    match run(&args) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::json!({
                    "import": "converted",
                    "schema_reference": SCHEMA_REFERENCE,
                    "converted": report.converted,
                    "unsupported": report.unsupported,
                    "policy": out,
                    "applied": false,
                })
            );
            ExitCode::SUCCESS
        }
        Err(failure) => {
            // The findings are the report: a refusal names every field whose
            // loss would change what the policy permits.
            println!(
                "{}",
                serde_json::json!({
                    "import": "refused",
                    "schema_reference": SCHEMA_REFERENCE,
                    "document_error": failure.document_error,
                    "converted": failure.report.converted,
                    "unsupported": failure.report.unsupported,
                    "policy": serde_json::Value::Null,
                    "applied": false,
                })
            );
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<ImportReport, ImportFailure> {
    let document = read(&args.input)?;
    let imported = openshell::import_openshell(&document)?;
    let policy_yaml = openshell::to_yaml(&imported.policy).map_err(|error| ImportFailure {
        document_error: Some(format!("converted policy did not serialize: {error}")),
        report: imported.report.clone(),
    })?;
    write(&args.out, policy_yaml.as_bytes())?;
    if let (Some(path), Some(l7)) = (&args.l7_out, &imported.l7) {
        let yaml = serde_yaml_ng::to_string(l7).map_err(|error| ImportFailure {
            document_error: Some(format!(
                "converted layer 7 rules did not serialize: {error}"
            )),
            report: imported.report.clone(),
        })?;
        write(path, yaml.as_bytes())?;
    }
    Ok(imported.report)
}

fn read(path: &Path) -> Result<String, ImportFailure> {
    let failure = |message: String| ImportFailure {
        document_error: Some(message),
        report: ImportReport::empty(),
    };
    let metadata = std::fs::metadata(path).map_err(|error| {
        failure(format!(
            "policy document {} is unreadable: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() || metadata.len() > MAX_DOCUMENT_BYTES {
        return Err(failure(format!(
            "policy document {} must be a regular file of at most {MAX_DOCUMENT_BYTES} bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| file.take(MAX_DOCUMENT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| {
            failure(format!(
                "policy document {} is unreadable: {error}",
                path.display()
            ))
        })?;
    String::from_utf8(bytes).map_err(|_| failure("policy document is not valid UTF-8".to_owned()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), ImportFailure> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| ImportFailure {
            document_error: Some(format!(
                "output directory {} is unwritable: {error}",
                parent.display()
            )),
            report: ImportReport::empty(),
        })?;
    }
    std::fs::write(path, bytes).map_err(|error| ImportFailure {
        document_error: Some(format!("{} is unwritable: {error}", path.display())),
        report: ImportReport::empty(),
    })
}
