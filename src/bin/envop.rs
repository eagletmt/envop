fn main() -> Result<(), anyhow::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let mut args = std::env::args();
    let me = args.next().unwrap();
    let account = args.next().unwrap_or_else(|| {
        eprintln!("Usage: {} ACCOUNT NAME PROG ARGS...", me);
        std::process::exit(1);
    });
    let name = args.next().unwrap_or_else(|| {
        eprintln!("Usage: {} ACCOUNT NAME PROG ARGS...", me);
        std::process::exit(1);
    });
    let prog = args.next().unwrap_or_else(|| {
        eprintln!("Usage: {} ACCOUNT NAME PROG ARGS...", me);
        std::process::exit(1);
    });
    let tags = std::env::var("ENVOP_TAGS").unwrap_or_else(|_| "".to_owned());
    let vault = std::env::var("ENVOP_VAULT").unwrap_or_else(|_| "".to_owned());
    let request = envop::GetCredentialsRequest {
        account,
        name,
        tags,
        vault,
    };

    let rt = tokio::runtime::Runtime::new()?;
    let resp = rt.block_on(get_credentials(request))?;

    let mut cmd = std::process::Command::new(&prog);
    cmd.envs(resp.credentials.into_iter()).args(args);
    let status = exec(cmd)?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

async fn get_credentials(
    request: envop::GetCredentialsRequest,
) -> Result<envop::GetCredentialsResponse, anyhow::Error> {
    use std::convert::TryFrom as _;

    let socket_path = std::env::var("ENVOP_AGENT_SOCK")?;
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_| {
            tokio::net::UnixStream::connect(socket_path.clone())
        }))
        .await?;
    let mut client = envop::agent_client::AgentClient::new(channel);

    let resp = client
        .get_credentials(tonic::Request::new(request.clone()))
        .await?
        .into_inner();
    if resp.ok {
        return Ok(resp);
    }

    let password = rpassword::read_password_from_tty(Some(&format!(
        "Enter password for 1Password ({}): ",
        request.account
    )))?;
    let resp = client
        .sign_in(tonic::Request::new(envop::SignInRequest {
            account: request.account.clone(),
            password,
        }))
        .await?
        .into_inner();
    if !resp.ok {
        return Err(anyhow::anyhow!("Failed to sign in: {}", resp.error));
    }

    let resp = client
        .get_credentials(tonic::Request::new(request.clone()))
        .await?
        .into_inner();
    if resp.ok {
        Ok(resp)
    } else {
        Err(anyhow::anyhow!("Failed to get credentials: {}", resp.error))
    }
}

#[cfg(unix)]
fn exec(mut cmd: std::process::Command) -> Result<std::process::ExitStatus, anyhow::Error> {
    use std::os::unix::process::CommandExt as _;
    Err(anyhow::Error::from(cmd.exec()))
}
