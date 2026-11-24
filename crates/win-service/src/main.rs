fn main() {
    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().collect();
        let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("run");
        let res = match cmd {
            "install" => maxq_win_service::windows_service::install_and_start_service(),
            "uninstall" => maxq_win_service::windows_service::stop_and_uninstall_service(),
            "run" => maxq_win_service::windows_service::run_service_dispatcher(),
            other => Err(format!("unknown command '{other}'; expected install|uninstall|run")),
        };
        if let Err(err) = res {
            eprintln!("maxq-service error: {err}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("maxq-service is a Windows-only TUN helper service binary.");
        std::process::exit(1);
    }
}
