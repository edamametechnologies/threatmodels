use edamame_foundation::runner_cli::run_cli;
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: run_cli_test <command> <username> [personate] [timeout]");
        process::exit(1);
    }

    let cmd = &args[1];
    let username = &args[2];
    let personate = args.get(3).map(|s| s == "true").unwrap_or(false);
    let timeout_opt = args
        .get(4)
        .and_then(|s| s.parse::<u64>().ok());

    match run_cli(cmd, username, personate, timeout_opt).await {
        Ok(output) => {
            print!("{}", output);
            process::exit(0);
        }
        Err(e) => {
            eprint!("{}", e);
            process::exit(1);
        }
    }
}
