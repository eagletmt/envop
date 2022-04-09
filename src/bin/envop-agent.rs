#[derive(Debug, structopt::StructOpt)]
struct Opt {
    #[structopt(long, help = "You have installed 1Password CLI v1 (legacy)")]
    use_1password_cli_v1: bool,
}

fn main() -> Result<(), anyhow::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
    use structopt::StructOpt as _;
    let opt = Opt::from_args();
    unsafe {
        disable_tracing();
        libc::setrlimit(
            libc::RLIMIT_CORE,
            &libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            },
        );
    }

    let old_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o077).unwrap());
    let socket_dir = tempfile::Builder::new().prefix("envop-agent-").tempdir()?;
    let parent_pid = std::process::id();
    let socket_path = socket_dir.path().join(format!("agent.{}.sock", parent_pid));

    if let nix::unistd::ForkResult::Parent { child } = unsafe { nix::unistd::fork() }? {
        println!(
            "ENVOP_AGENT_SOCK={}; export ENVOP_AGENT_SOCK;",
            socket_path.display()
        );
        println!("ENVOP_AGENT_PID={}; export ENVOP_AGENT_PID;", child);
        std::process::exit(0);
    }

    nix::unistd::setsid()?;
    std::env::set_current_dir("/")?;
    let child_pid = std::process::id();
    {
        use std::os::unix::io::AsRawFd as _;
        let stdin = std::fs::File::open("/dev/null")?;
        nix::unistd::dup2(stdin.as_raw_fd(), std::io::stdin().as_raw_fd())?;
        let stdout =
            std::fs::File::create(socket_dir.path().join(format!("stdout.{}.log", child_pid)))?;
        let stderr =
            std::fs::File::create(socket_dir.path().join(format!("stderr.{}.log", child_pid)))?;
        nix::unistd::dup2(stdout.as_raw_fd(), std::io::stdout().as_raw_fd())?;
        nix::unistd::dup2(stderr.as_raw_fd(), std::io::stderr().as_raw_fd())?;
    }

    let child_pid = std::process::id();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use futures::TryFutureExt as _;

        let incoming = {
            let uds = tokio::net::UnixListener::bind(&socket_path)?;
            async_stream::stream! {
                loop {
                    let item = uds.accept().map_ok(|(st, _)| UnixStream(st)).await;
                    yield item;
                }
            }
        };
        nix::sys::stat::umask(old_umask);

        tracing::info!(socket_path = %socket_path.display(), %child_pid, "Starting server");
        tonic::transport::Server::builder()
            .add_service(envop::agent_server::AgentServer::new(Agent::new(opt)))
            .serve_with_incoming_shutdown(incoming, shutdown())
            .await?;
        tracing::info!("Exiting");

        Ok(())
    })
}

#[cfg(target_os = "linux")]
unsafe fn disable_tracing() {
    libc::prctl(libc::PR_SET_DUMPABLE, 0);
}

#[cfg(target_os = "macos")]
unsafe fn disable_tracing() {
    libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
}

#[derive(Clone)]
struct Token {
    account: String,
    token: secrecy::Secret<String>,
}

struct Agent {
    token: std::sync::Arc<std::sync::Mutex<Option<Token>>>,
    use_1password_cli_v1: bool,
}

impl Agent {
    fn new(opt: Opt) -> Self {
        Self {
            token: Default::default(),
            use_1password_cli_v1: opt.use_1password_cli_v1,
        }
    }

    async fn get_credentials_v1(
        &self,
        token: Token,
        vault: &str,
        tags: &str,
        name: &str,
    ) -> Result<tonic::Response<envop::GetCredentialsResponse>, tonic::Status> {
        use secrecy::ExposeSecret as _;
        let session_name = format!("OP_SESSION_{}", token.account);
        let output = tokio::process::Command::new("op")
            .env(&session_name, token.token.expose_secret())
            .arg("list")
            .arg("items")
            .arg("--vault")
            .arg(&vault)
            .arg("--categories")
            .arg("Secure Note")
            .arg("--tags")
            .arg(&tags)
            .output()
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to spawn op(1): {}", e)))?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Ok(tonic::Response::new(envop::GetCredentialsResponse {
                ok: false,
                error,
                ..Default::default()
            }));
        }

        let item_summaries: Vec<ItemSummaryV1> =
            serde_json::from_slice(&output.stdout).map_err(|e| {
                tonic::Status::internal(format!(
                    "Failed to deserialize `op list items` output: {}",
                    e
                ))
            })?;
        let mut credentials = std::collections::HashMap::new();
        for item_summary in item_summaries
            .into_iter()
            .filter(|item_summary| item_summary.overview.title == name)
        {
            let output = std::process::Command::new("op")
                .env(&session_name, token.token.expose_secret())
                .arg("get")
                .arg("item")
                .arg("--vault")
                .arg(&vault)
                .arg(&item_summary.uuid)
                .output()?;
            if !output.status.success() {
                eprintln!("`op get item {}` failed", item_summary.uuid);
                let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                return Ok(tonic::Response::new(envop::GetCredentialsResponse {
                    ok: false,
                    error,
                    ..Default::default()
                }));
            }
            let item: ItemV1 = serde_json::from_slice(&output.stdout).map_err(|e| {
                tonic::Status::internal(format!(
                    "Failed to deserialize `op get item` output: {}",
                    e
                ))
            })?;
            for section in item.details.sections.into_iter() {
                for field in section.fields.into_iter() {
                    if field.k == "string" || field.k == "concealed" {
                        credentials.insert(field.t, field.v);
                    } else {
                        tracing::info!(field = %field.t, item = %item_summary.uuid, "Ignoring unknown field in item");
                    }
                }
            }
        }

        Ok(tonic::Response::new(envop::GetCredentialsResponse {
            ok: true,
            credentials,
            ..Default::default()
        }))
    }

    async fn get_credentials_v2(
        &self,
        token: Token,
        vault: &str,
        tags: &str,
        name: &str,
    ) -> Result<tonic::Response<envop::GetCredentialsResponse>, tonic::Status> {
        use secrecy::ExposeSecret as _;
        let session_name = format!("OP_SESSION_{}", token.account);
        let output = tokio::process::Command::new("op")
            .env(&session_name, token.token.expose_secret())
            .arg("item")
            .arg("list")
            .arg("--format")
            .arg("json")
            .arg("--vault")
            .arg(&vault)
            .arg("--categories")
            .arg("Secure Note")
            .arg("--tags")
            .arg(&tags)
            .output()
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to spawn op(1): {}", e)))?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Ok(tonic::Response::new(envop::GetCredentialsResponse {
                ok: false,
                error,
                ..Default::default()
            }));
        }

        let item_summaries: Vec<ItemSummaryV2> =
            serde_json::from_slice(&output.stdout).map_err(|e| {
                tonic::Status::internal(format!(
                    "Failed to deserialize `op item list` output: {}",
                    e
                ))
            })?;
        let mut credentials = std::collections::HashMap::new();
        for item_summary in item_summaries
            .into_iter()
            .filter(|item_summary| item_summary.title == name)
        {
            let output = std::process::Command::new("op")
                .env(&session_name, token.token.expose_secret())
                .arg("item")
                .arg("get")
                .arg("--format")
                .arg("json")
                .arg("--vault")
                .arg(&vault)
                .arg(&item_summary.id)
                .output()?;
            if !output.status.success() {
                eprintln!("`op item get {}` failed", item_summary.id);
                let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                return Ok(tonic::Response::new(envop::GetCredentialsResponse {
                    ok: false,
                    error,
                    ..Default::default()
                }));
            }
            let item: ItemV2 = serde_json::from_slice(&output.stdout).map_err(|e| {
                tonic::Status::internal(format!(
                    "Failed to deserialize `op item get` output: {}",
                    e
                ))
            })?;
            for field in item.fields.into_iter() {
                if let Some(value) = field.value {
                    if field.type_ == "STRING" || field.type_ == "CONCEALED" {
                        credentials.insert(field.label, value);
                    } else {
                        tracing::info!(field = %field.label, item = %item_summary.id, "Ignoring unknown field in item");
                    }
                }
            }
        }

        Ok(tonic::Response::new(envop::GetCredentialsResponse {
            ok: true,
            credentials,
            ..Default::default()
        }))
    }
}

#[tonic::async_trait]
impl envop::agent_server::Agent for Agent {
    async fn sign_in(
        &self,
        request: tonic::Request<envop::SignInRequest>,
    ) -> Result<tonic::Response<envop::SignInResponse>, tonic::Status> {
        use tokio::io::AsyncWriteExt as _;

        let message = request.into_inner();
        let mut cmd = tokio::process::Command::new("op");
        cmd.arg("signin").arg("--raw");
        if !self.use_1password_cli_v1 {
            cmd.arg("--account");
        }
        let mut child = cmd
            .arg(&message.account)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| tonic::Status::internal(format!("Failed to spawn op(1): {}", e)))?;
        {
            let mut stdin = child.stdin.take().unwrap();
            stdin
                .write_all(message.password.as_bytes())
                .await
                .map_err(|e| tonic::Status::internal(format!("Failed to write password: {}", e)))?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| tonic::Status::internal(format!("Failed to wait op(1) process: {}", e)))?;
        if output.status.success() {
            let token =
                secrecy::Secret::new(String::from_utf8_lossy(&output.stdout).trim().to_owned());
            {
                let mut token_ptr = self.token.lock().map_err(|e| {
                    tonic::Status::internal(format!("Failed to lock internal token: {}", e))
                })?;
                *token_ptr = Some(Token {
                    account: message.account,
                    token,
                });
            }
            tracing::info!("Token was refreshed");
            Ok(tonic::Response::new(envop::SignInResponse {
                ok: true,
                error: "".to_owned(),
            }))
        } else {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            tracing::info!(%error, "SignIn was failed");
            Ok(tonic::Response::new(envop::SignInResponse {
                ok: false,
                error,
            }))
        }
    }

    async fn get_credentials(
        &self,
        request: tonic::Request<envop::GetCredentialsRequest>,
    ) -> Result<tonic::Response<envop::GetCredentialsResponse>, tonic::Status> {
        let message = request.into_inner();
        let vault = if message.vault.is_empty() {
            "Private"
        } else {
            &message.vault
        };
        let tags = if message.tags.is_empty() {
            "envop"
        } else {
            &message.tags
        };

        let token = {
            let token_ptr = self.token.lock().map_err(|e| {
                tonic::Status::internal(format!("Failed to lock internal token: {}", e))
            })?;
            if token_ptr.is_none() {
                return Ok(tonic::Response::new(envop::GetCredentialsResponse {
                    ok: false,
                    error: "Sign in was never called".to_owned(),
                    ..Default::default()
                }));
            }
            token_ptr.as_ref().unwrap().clone()
        };

        if self.use_1password_cli_v1 {
            self.get_credentials_v1(token, vault, tags, &message.name)
                .await
        } else {
            self.get_credentials_v2(token, vault, tags, &message.name)
                .await
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct ItemSummaryV1 {
    uuid: String,
    overview: ItemOverview,
}

#[derive(Debug, serde::Deserialize)]
struct ItemOverview {
    title: String,
}

#[derive(Debug, serde::Deserialize)]
struct ItemV1 {
    details: ItemDetailsV1,
}

#[derive(Debug, serde::Deserialize)]
struct ItemDetailsV1 {
    sections: Vec<ItemSectionV1>,
}

#[derive(Debug, serde::Deserialize)]
struct ItemSectionV1 {
    fields: Vec<ItemFieldV1>,
}

#[derive(Debug, serde::Deserialize)]
struct ItemFieldV1 {
    k: String,
    t: String,
    v: String,
}

#[derive(Debug, serde::Deserialize)]
struct ItemSummaryV2 {
    id: String,
    title: String,
}

#[derive(Debug, serde::Deserialize)]
struct ItemV2 {
    fields: Vec<ItemFieldV2>,
}

#[derive(Debug, serde::Deserialize)]
struct ItemFieldV2 {
    #[serde(rename = "type")]
    type_: String,
    label: String,
    value: Option<String>,
}

async fn shutdown() {
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("Failed to set signal handler for SIGINT");
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("Failed to set signal handler for SIGTERM");
    let sig = tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    };
    tracing::info!("Got {}", sig);
}

// https://github.com/hyperium/tonic/blob/v0.6.2/examples/src/uds/server.rs
#[derive(Debug)]
struct UnixStream(tokio::net::UnixStream);

impl tonic::transport::server::Connected for UnixStream {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        UdsConnectInfo {
            peer_addr: self.0.peer_addr().ok().map(std::sync::Arc::new),
            peer_cred: self.0.peer_cred().ok(),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct UdsConnectInfo {
    peer_addr: Option<std::sync::Arc<tokio::net::unix::SocketAddr>>,
    peer_cred: Option<tokio::net::unix::UCred>,
}

impl tokio::io::AsyncRead for UnixStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for UnixStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
