use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinSet;

const PLAN_SCHEMA: &str = "fidb-staged-backend-plan/v1";
const RESULT_SCHEMA: &str = "fidb-rust-staged-result/v1";
const SERVICE_FRAME: &str = "FIDB_RESULT\t";
const MAX_DIAGNOSTICS_PER_WORKER: usize = 32;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    index: usize,
    job_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema_version: String,
    project_root: PathBuf,
    python: PathBuf,
    worker_module: String,
    build_workers: usize,
    analysis_workers: usize,
    build_jobs_per_cell: usize,
    java_options: String,
    verbose: bool,
    jobs: Vec<Job>,
}

#[derive(Debug, Serialize)]
struct ResultDocument {
    schema_version: &'static str,
    backend: &'static str,
    wall_time_ns: u128,
    build_results: Vec<Value>,
    analysis_results: Vec<Value>,
    errors: Vec<String>,
    diagnostics: Vec<String>,
}

async fn run_build(plan: Arc<Plan>, job: Job) -> Result<Value, String> {
    let mut command = Command::new(&plan.python);
    command
        .arg("-m")
        .arg(&plan.worker_module)
        .arg("build")
        .arg("--job")
        .arg(&job.job_path)
        .arg("--build-jobs")
        .arg(plan.build_jobs_per_cell.to_string())
        .current_dir(&plan.project_root)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if plan.verbose {
        command.arg("--verbose");
    }
    let output = command
        .output()
        .await
        .map_err(|error| format!("build {} could not start: {error}", job.job_path.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .next_back()
        .ok_or_else(|| {
            format!(
                "build {} emitted no result; stderr={}",
                job.job_path.display(),
                String::from_utf8_lossy(&output.stderr)
            )
        })?;
    let result: Value = serde_json::from_str(line).map_err(|error| {
        format!(
            "build {} emitted invalid JSON: {error}; stdout={stdout:?}",
            job.job_path.display()
        )
    })?;
    if result.get("index").and_then(Value::as_u64) != Some(job.index as u64) {
        return Err(format!(
            "build {} returned the wrong job index",
            job.job_path.display()
        ));
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "build {} exited {}; result={result}; stderr={stderr}",
            job.job_path.display(),
            output.status
        ));
    }
    Ok(result)
}

async fn analysis_worker(
    worker_id: usize,
    plan: Arc<Plan>,
    receiver: Arc<Mutex<mpsc::Receiver<Job>>>,
) -> (Vec<Value>, Vec<String>, Vec<String>) {
    let mut command = Command::new(&plan.python);
    command
        .arg("-m")
        .arg(&plan.worker_module)
        .arg("service")
        // JAVA_TOOL_OPTIONS begins with "-Xmx".  Keeping option and value in
        // one argv token prevents Python argparse treating that value as a
        // second option.
        .arg(format!("--java-options={}", plan.java_options))
        .current_dir(&plan.project_root)
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if plan.verbose {
        command.arg("--verbose");
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return (
                Vec::new(),
                vec![format!(
                    "analysis worker {worker_id} could not start: {error}"
                )],
                Vec::new(),
            );
        }
    };
    let Some(mut stdin) = child.stdin.take() else {
        return (
            Vec::new(),
            vec![format!("analysis worker {worker_id} has no stdin")],
            Vec::new(),
        );
    };
    let Some(stdout) = child.stdout.take() else {
        return (
            Vec::new(),
            vec![format!("analysis worker {worker_id} has no stdout")],
            Vec::new(),
        );
    };
    let mut stdout = BufReader::new(stdout);
    let stderr_task = child.stderr.take().map(|stderr| {
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut text = String::new();
            let _ = reader.read_to_string(&mut text).await;
            text
        })
    });
    let mut results = Vec::new();
    let mut errors = Vec::new();
    let mut diagnostics = Vec::new();
    let mut suppressed_diagnostics = 0usize;
    loop {
        let job = {
            let mut guarded = receiver.lock().await;
            guarded.recv().await
        };
        let Some(job) = job else { break };
        let request = json!({"job_path": job.job_path});
        let mut payload = match serde_json::to_vec(&request) {
            Ok(payload) => payload,
            Err(error) => {
                errors.push(format!(
                    "analysis worker {worker_id} could not encode job {}: {error}",
                    job.job_path.display()
                ));
                continue;
            }
        };
        payload.push(b'\n');
        if let Err(error) = stdin.write_all(&payload).await {
            errors.push(format!(
                "analysis worker {worker_id} write failed for {}: {error}",
                job.job_path.display()
            ));
            break;
        }
        if let Err(error) = stdin.flush().await {
            errors.push(format!(
                "analysis worker {worker_id} flush failed for {}: {error}",
                job.job_path.display()
            ));
            break;
        }
        let framed = loop {
            let mut line = String::new();
            match stdout.read_line(&mut line).await {
                Ok(0) => {
                    errors.push(format!(
                        "analysis worker {worker_id} exited before job {} completed",
                        job.job_path.display()
                    ));
                    break None;
                }
                Ok(_) => {
                    if let Some(payload) = line.trim_end().strip_prefix(SERVICE_FRAME) {
                        break Some(payload.to_string());
                    }
                    if !line.trim().is_empty() {
                        if diagnostics.len() < MAX_DIAGNOSTICS_PER_WORKER {
                            diagnostics.push(format!(
                                "analysis worker {worker_id} stdout: {}",
                                line.trim_end()
                            ));
                        } else {
                            suppressed_diagnostics += 1;
                        }
                    }
                }
                Err(error) => {
                    errors.push(format!(
                        "analysis worker {worker_id} read failed for {}: {error}",
                        job.job_path.display()
                    ));
                    break None;
                }
            }
        };
        let Some(framed) = framed else { break };
        match serde_json::from_str::<Value>(&framed) {
                Ok(result) => {
                    if result.get("index").and_then(Value::as_u64)
                        != Some(job.index as u64)
                    {
                        errors.push(format!(
                            "analysis worker {worker_id} returned the wrong index for {}",
                            job.job_path.display()
                        ));
                        continue;
                    }
                    if result
                        .get("pipeline_error")
                        .and_then(Value::as_str)
                        .is_some_and(|value| !value.is_empty())
                    {
                        errors.push(format!(
                            "analysis worker {worker_id} job {} failed: {}",
                            job.job_path.display(),
                            result["pipeline_error"]
                        ));
                    }
                    results.push(result);
                }
                Err(error) => errors.push(format!(
                    "analysis worker {worker_id} returned invalid JSON for {}: {error}; frame={framed:?}",
                    job.job_path.display()
                )),
        }
    }
    drop(stdin);
    match child.wait().await {
        Ok(status) if !status.success() => {
            errors.push(format!("analysis worker {worker_id} exited {status}"));
        }
        Err(error) => errors.push(format!("analysis worker {worker_id} wait failed: {error}")),
        _ => {}
    }
    if let Some(task) = stderr_task
        && let Ok(stderr) = task.await
        && !stderr.trim().is_empty()
    {
        // Ghidra/Java routinely report launcher information on stderr.  The
        // service exit status and machine result determine failure; preserve
        // stderr as a diagnostic without converting it into a false error.
        diagnostics.push(format!(
            "analysis worker {worker_id} stderr:\n{}",
            stderr.trim()
        ));
    }
    if suppressed_diagnostics > 0 {
        diagnostics.push(format!(
            "analysis worker {worker_id}: suppressed {suppressed_diagnostics} additional stdout diagnostics"
        ));
    }
    (results, errors, diagnostics)
}

fn result_index(value: &Value) -> u64 {
    value
        .get("index")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX)
}

async fn execute(plan: Plan) -> ResultDocument {
    let started = Instant::now();
    let plan = Arc::new(plan);
    let (sender, receiver) = mpsc::channel::<Job>((plan.analysis_workers * 2).max(1));
    let receiver = Arc::new(Mutex::new(receiver));
    let mut analysis_tasks = JoinSet::new();
    for worker_id in 1..=plan.analysis_workers {
        analysis_tasks.spawn(analysis_worker(worker_id, plan.clone(), receiver.clone()));
    }

    let semaphore = Arc::new(Semaphore::new(plan.build_workers));
    let build_results = Arc::new(Mutex::new(Vec::<Value>::new()));
    let build_errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut build_tasks = JoinSet::new();
    for job in plan.jobs.clone() {
        let plan = plan.clone();
        let semaphore = semaphore.clone();
        let results = build_results.clone();
        let errors = build_errors.clone();
        let sender = sender.clone();
        build_tasks.spawn(async move {
            let permit = semaphore.acquire_owned().await;
            if permit.is_err() {
                errors.lock().await.push(format!(
                    "build scheduler closed before {}",
                    job.job_path.display()
                ));
                return;
            }
            match run_build(plan, job.clone()).await {
                Ok(result) => {
                    results.lock().await.push(result);
                    if sender.send(job).await.is_err() {
                        errors
                            .lock()
                            .await
                            .push("analysis queue closed during build".to_string());
                    }
                }
                Err(error) => errors.lock().await.push(error),
            }
        });
    }
    drop(sender);
    while let Some(completed) = build_tasks.join_next().await {
        if let Err(error) = completed {
            build_errors
                .lock()
                .await
                .push(format!("build task join failed: {error}"));
        }
    }

    let mut analysis_results = Vec::new();
    let mut diagnostics = Vec::new();
    let mut errors = build_errors.lock().await.clone();
    while let Some(completed) = analysis_tasks.join_next().await {
        match completed {
            Ok((mut worker_results, mut worker_errors, mut worker_diagnostics)) => {
                analysis_results.append(&mut worker_results);
                errors.append(&mut worker_errors);
                diagnostics.append(&mut worker_diagnostics);
            }
            Err(error) => errors.push(format!("analysis task join failed: {error}")),
        }
    }
    let mut build_results = build_results.lock().await.clone();
    build_results.sort_by_key(result_index);
    analysis_results.sort_by_key(result_index);
    ResultDocument {
        schema_version: RESULT_SCHEMA,
        backend: "rust-staged-v1",
        wall_time_ns: started.elapsed().as_nanos(),
        build_results,
        analysis_results,
        errors,
        diagnostics,
    }
}

fn read_plan(path: &Path) -> Result<Plan, String> {
    let payload = std::fs::read(path)
        .map_err(|error| format!("cannot read plan {}: {error}", path.display()))?;
    let plan: Plan = serde_json::from_slice(&payload)
        .map_err(|error| format!("invalid plan {}: {error}", path.display()))?;
    if plan.schema_version != PLAN_SCHEMA {
        return Err(format!("unsupported plan schema: {}", plan.schema_version));
    }
    if plan.build_workers == 0 || plan.analysis_workers == 0 {
        return Err("worker counts must be positive".to_string());
    }
    if plan.jobs.is_empty() {
        return Err("plan must contain jobs".to_string());
    }
    if !plan.project_root.is_absolute()
        || !plan.python.is_absolute()
        || plan.jobs.iter().any(|job| !job.job_path.is_absolute())
    {
        return Err("project, Python and job paths must be absolute".to_string());
    }
    Ok(plan)
}

fn atomic_write(path: &Path, result: &ResultDocument) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(result)
        .map_err(|error| format!("cannot encode result: {error}"))?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&temporary, payload)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("cannot publish {}: {error}", path.display()))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() != 3 {
        eprintln!("usage: fidb-rust-staged PLAN.json RESULT.json");
        std::process::exit(2);
    }
    let plan_path = PathBuf::from(&arguments[1]);
    let result_path = PathBuf::from(&arguments[2]);
    let plan = match read_plan(&plan_path) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    };
    let result = execute(plan).await;
    let exit_code = if result.errors.is_empty() { 0 } else { 1 };
    if let Err(error) = atomic_write(&result_path, &result) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    if exit_code != 0 {
        eprintln!("error: staged run recorded {} errors", result.errors.len());
    }
    std::process::exit(exit_code);
}
