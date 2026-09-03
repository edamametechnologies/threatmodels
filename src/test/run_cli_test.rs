use edamame_foundation::runner_cli::run_cli;
use std::env;
use std::process;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // `run_cli_test dump-ai-framework-tags` prints the AI Agent Posture
    // framework crosswalk (check name -> threat-model tags) as JSON, straight
    // from edamame_foundation::agent_framework_tags -- the same tables the
    // app's OWASP / ATLAS / Trust Controls scorecards render. Consumed by
    // src/publish/sync-ai-framework-tags.py (apply + CI drift check).
    if args.get(1).map(String::as_str) == Some("dump-ai-framework-tags") {
        let definitions = edamame_foundation::supported_agents::ordered_supported_agents();
        let agents: Vec<&str> = definitions.iter().map(|d| d.agent_type.as_str()).collect();
        let catalog = edamame_foundation::agent_framework_tags::ai_framework_tag_catalog(&agents);
        println!("{}", serde_json::to_string_pretty(&catalog).expect("serializable catalog"));
        return;
    }

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
