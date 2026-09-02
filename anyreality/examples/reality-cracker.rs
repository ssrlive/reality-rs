//! reality-cracker: a TLS-record-aware HTTP CONNECT proxy for observing anyreality client traffic.
//! Copied from https://github.com/Anonymous376c1d0cf28/VLESS-cracker
//!
//! This example tracks the first ClientHello / ServerHello on a proxied CONNECT
//! tunnel and runs a background replay probe modeled after the vless-cracker
//! sample: after a real TLS 1.3 ServerHello is observed, it replays the original
//! ClientHello twice (A/B), randomizes the legacy_session_id for B, sends a set
//! of application-data probes after the first response arrives, and classifies
//! each probe as ALERT / FIN / RST / TIMEOUT / NONE.

use core::time::Duration;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedReadHalf};
use tokio::time::{Instant, sleep, timeout};

const REPLAY_TIMEOUT: Duration = Duration::from_secs(3);
const PROBE_OBSERVE_TIMEOUT: Duration = Duration::from_secs(4);
const PROBE_REPLAY_DELAY: Duration = Duration::from_secs(1);
const REQUIRED_CONFIRMATION_ROUNDS: u32 = 3;
const TLS13_SELECTED_VERSION: u16 = 0x0304;
const TLS13_ENCRYPTED_ALERT_RECORD_LEN: u16 = 19;
const DEFAULT_PROBE_LINES: [&str; 7] = [
    "14 03 03 00 01 01 14 03 03 00 01 01 14 03 03 00 01 01",
    "17 99 99 00 10",
    "17 03 03 42 00",
    "14 03 03 00 02 01 01",
    "14 03 03 00 01 02",
    "14 03 01 00 01 01",
    "14 03 03 00 05 01 01 01 01 01",
];

#[derive(Debug, Default)]
struct ConnectionState {
    client_hello_printed: bool,
    server_hello_printed: bool,
    replay_started: bool,
    observed_client_hello: Option<Vec<u8>>,
    observed_sni: String,
}

#[derive(Debug, Default, Clone, Copy)]
struct ServerProbeState {
    in_progress: bool,
    excluded: bool,
    matched_rounds: u32,
}

type SharedProbeStates = Arc<Mutex<HashMap<String, ServerProbeState>>>;

#[derive(Debug, Default, Clone)]
struct ClientHelloInfo {
    legacy_version: u16,
    record_version_major: u8,
    record_version_minor: u8,
    cipher_suite_count: usize,
    extension_count: usize,
    sni: String,
    alpn: String,
    supported_versions: String,
}

#[derive(Debug, Default, Clone, Copy)]
struct ServerHelloInfo {
    selected_version: u16,
}

#[derive(Debug, Clone)]
struct ProbeSpec {
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeStatus {
    None,
    Alert,
    Fin,
    Rst,
    Timeout,
}

#[derive(Debug, Clone, Copy)]
struct AppDataCloseProbe {
    status: ProbeStatus,
    sent: bool,
}

impl Default for AppDataCloseProbe {
    fn default() -> Self {
        Self {
            status: ProbeStatus::None,
            sent: false,
        }
    }
}

#[derive(Debug, Clone)]
struct ReplayProbeResult {
    appdata_close: AppDataCloseProbe,
    got_response: bool,
    connection_failed: bool,
    final_status: ReplayStatus,
}

impl Default for ReplayProbeResult {
    fn default() -> Self {
        Self {
            appdata_close: AppDataCloseProbe::default(),
            got_response: false,
            connection_failed: false,
            final_status: ReplayStatus::NoResponse,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayStatus {
    Ok,
    SocketFailed,
    NonblockFailed,
    BindFailed,
    ConnectFailed,
    SendFailed,
    Timeout,
    Closed,
    RecvFailed,
    BufferFull,
    NoResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayRoundStatus {
    Valid,
    ConnectionError,
    NoSignal,
    InternalError,
}

#[derive(Debug, Parser)]
#[command(
    version,
    name = "reality-cracker",
    about = "TLS-record-aware HTTP CONNECT probe proxy",
    long_about = None
)]
struct CliConfig {
    #[arg(default_value = "127.0.0.1:12345")]
    bind_addr: SocketAddr,

    #[arg(long = "probe", value_name = "HEX")]
    probe_lines: Vec<String>,

    #[arg(long = "probe-file", value_name = "PATH")]
    probe_files: Vec<std::path::PathBuf>,

    #[arg(long = "probe-mode", value_enum, default_value_t = ProbeMode::Replace)]
    probe_mode: ProbeMode,

    /// Log filter (off/error/warn/info/debug/trace or env-style spec).
    #[arg(long, default_value = "info")]
    log: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum ProbeMode {
    #[default]
    Replace,
    Append,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = CliConfig::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(cli.log.clone()))
        .init();

    let probes = Arc::new(load_probes(&cli)?);
    let probe_states: SharedProbeStates = Arc::new(Mutex::new(HashMap::new()));
    let listener = TcpListener::bind(&cli.bind_addr).await?;
    log::info!(
        "reality-cracker started on {} with {} probe(s)",
        listener.local_addr()?,
        probes.len()
    );

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let probes = probes.clone();
                let probe_states = probe_states.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, probes, probe_states).await;
                });
            }
            Err(err) => {
                log::error!("accept error: {}", err);
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    probes: Arc<Vec<ProbeSpec>>,
    probe_states: SharedProbeStates,
) -> std::io::Result<()> {
    let peer_addr = stream.peer_addr()?;
    let (stream_reader, mut client_writer) = stream.into_split();
    let (method, target, mut request_reader) = read_request(stream_reader).await?;

    if !method.eq_ignore_ascii_case("CONNECT") {
        log::warn!("from {} rejected {}", peer_addr, target);
        return Ok(());
    }

    log::info!("from {} accepted {}", peer_addr, target);

    let upstream = TcpStream::connect(&target).await?;
    let upstream_peer = upstream.peer_addr()?;
    let upstream_key = upstream_peer.to_string();
    let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
    client_writer
        .write_all(response)
        .await?;
    let (mut server_reader, mut server_writer) = upstream.into_split();

    let state = Arc::new(Mutex::new(ConnectionState::default()));

    let client_state = Arc::clone(&state);
    let target_for_log = target.clone();
    let client_to_server = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut sniff_buffer = Vec::new();

        loop {
            let n = match request_reader.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => n,
                Err(err) => {
                    log::error!("client->server read error for {}: {}", target_for_log, err);
                    return;
                }
            };

            sniff_buffer.extend_from_slice(&buf[..n]);
            if let Some((hello, record_len)) = parse_client_hello(&sniff_buffer) {
                let mut guard = client_state.lock().unwrap();
                if !guard.client_hello_printed {
                    guard.client_hello_printed = true;
                    guard.observed_client_hello = Some(sniff_buffer[..record_len].to_vec());
                    guard.observed_sni = hello.sni.clone();
                    log::info!("{}", format_client_hello(&target_for_log, &hello));
                }
                sniff_buffer.clear();
            }

            if let Err(err) = server_writer.write_all(&buf[..n]).await {
                log::error!("client->server write error for {}: {}", target_for_log, err);
                return;
            }
        }
    });

    let server_state = Arc::clone(&state);
    let target_for_probe = target.clone();
    let upstream_key_for_probe = upstream_key.clone();
    let shared_probe_states = probe_states.clone();
    let server_to_client = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut sniff_buffer = Vec::new();

        loop {
            let n = match server_reader.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => n,
                Err(err) => {
                    log::error!(
                        "server->client read error for {}: {}",
                        target_for_probe,
                        err
                    );
                    return;
                }
            };

            sniff_buffer.extend_from_slice(&buf[..n]);
            if let Some(info) = parse_server_hello(&sniff_buffer) {
                let mut replay_args = None;
                {
                    let mut guard = server_state.lock().unwrap();
                    if !guard.server_hello_printed {
                        guard.server_hello_printed = true;
                        log::info!("{}", format_server_hello(&target_for_probe, &info));
                    }

                    if info.selected_version == TLS13_SELECTED_VERSION && !guard.replay_started {
                        if let Some(client_hello) = guard.observed_client_hello.clone() {
                            if let Some(round_no) = start_server_probe_round(
                                &shared_probe_states,
                                &upstream_key_for_probe,
                            ) {
                                guard.replay_started = true;
                                replay_args = Some((
                                    target_for_probe.clone(),
                                    upstream_key_for_probe.clone(),
                                    guard.observed_sni.clone(),
                                    client_hello,
                                    probes.clone(),
                                    shared_probe_states.clone(),
                                    round_no,
                                ));
                            } else {
                                guard.replay_started = true;
                            }
                        }
                    }
                }

                if let Some((
                    target,
                    server_key,
                    sni,
                    client_hello,
                    probes,
                    shared_probe_states,
                    round_no,
                )) = replay_args
                {
                    tokio::spawn(async move {
                        run_replay_probe(
                            &target,
                            &server_key,
                            &sni,
                            client_hello,
                            probes,
                            shared_probe_states,
                            round_no,
                        )
                        .await;
                    });
                }
                sniff_buffer.clear();
            }

            if let Err(err) = client_writer.write_all(&buf[..n]).await {
                log::error!(
                    "server->client write error for {}: {}",
                    target_for_probe,
                    err
                );
                return;
            }
        }
    });

    let _ = tokio::join!(client_to_server, server_to_client);
    Ok(())
}

async fn run_replay_probe(
    target: &str,
    server_key: &str,
    sni: &str,
    client_hello: Vec<u8>,
    probes: Arc<Vec<ProbeSpec>>,
    probe_states: SharedProbeStates,
    round_no: u32,
) {
    let a = run_replay_probe_round(server_key, &client_hello, 1, probes.as_slice()).await;

    let mut randomized = client_hello.clone();
    let mut session_id_len = 0u8;
    let mut before_hash = 0u32;
    let mut after_hash = 0u32;
    if randomize_client_hello_legacy_session_id(
        &mut randomized,
        &mut session_id_len,
        &mut before_hash,
        &mut after_hash,
    ) {
        log::info!(
            "TLS replay B randomized ClientHello legacy_session_id len={} before={:08x} after={:08x}",
            session_id_len,
            before_hash,
            after_hash
        );
    } else {
        log::info!("TLS replay B skipped ClientHello legacy_session_id randomization");
    }

    log::info!(
        "TLS replay waiting {}s before attempt=B randomized session_id recheck",
        PROBE_REPLAY_DELAY.as_secs()
    );
    sleep(PROBE_REPLAY_DELAY).await;
    let b = run_replay_probe_round(server_key, &randomized, 2, probes.as_slice()).await;

    if a.status != ReplayRoundStatus::Valid || b.status != ReplayRoundStatus::Valid {
        let _ = finish_server_probe_round(&probe_states, server_key, false, true);
        log::info!(
            "TLS replay confirmation round={} server={} target={} skipped A={} B={}",
            round_no,
            server_key,
            target,
            replay_round_status_name(a.status),
            replay_round_status_name(b.status)
        );
        return;
    }

    let mismatch = !probe_rounds_match(&a.results, &b.results);
    let alarm_condition = replay_probe_matches_alarm_condition(&a.results, &b.results);
    let round_matches = alarm_condition;
    let (matched_rounds, final_match) =
        finish_server_probe_round(&probe_states, server_key, round_matches, false);

    if round_matches && !final_match {
        log::info!(
            "TLS replay confirmation round={}/{} passed server={} target={}",
            matched_rounds,
            REQUIRED_CONFIRMATION_ROUNDS,
            server_key,
            target
        );
        return;
    }

    if !round_matches {
        log::info!(
            "TLS replay confirmation failed; excluding server={} target={} round={}",
            server_key,
            target,
            round_no
        );
        return;
    }

    let comparison_summary = format!("cmp=X[{}]", if mismatch { 'D' } else { 'E' });
    let result_summary = format!(
        "A{{X={}}}|B{{X={}}}",
        format_probe_status_list(&a.results),
        format_probe_status_list(&b.results)
    );
    let sni_value = if sni.is_empty() { "-" } else { sni };

    log::warn!(
        "TLS ReplayProbe MISMATCH, REALITY connection detected after {}/{} confirmations. server={} target={} sni={} probes={} {} result={}",
        REQUIRED_CONFIRMATION_ROUNDS,
        REQUIRED_CONFIRMATION_ROUNDS,
        server_key,
        target,
        sni_value,
        a.results.len(),
        comparison_summary,
        result_summary
    );
}

fn start_server_probe_round(probe_states: &SharedProbeStates, target: &str) -> Option<u32> {
    let mut guard = probe_states.lock().unwrap();
    let state = guard
        .entry(target.to_string())
        .or_default();
    if state.excluded || state.in_progress || state.matched_rounds >= REQUIRED_CONFIRMATION_ROUNDS {
        return None;
    }

    state.in_progress = true;
    Some(state.matched_rounds + 1)
}

fn finish_server_probe_round(
    probe_states: &SharedProbeStates,
    target: &str,
    matched: bool,
    retry_later: bool,
) -> (u32, bool) {
    let mut guard = probe_states.lock().unwrap();
    let Some(state) = guard.get_mut(target) else {
        return (0, false);
    };

    state.in_progress = false;
    if retry_later {
        return (state.matched_rounds, false);
    }

    if matched {
        state.matched_rounds += 1;
        if state.matched_rounds >= REQUIRED_CONFIRMATION_ROUNDS {
            state.excluded = true;
            return (state.matched_rounds, true);
        }
        return (state.matched_rounds, false);
    }

    state.excluded = true;
    (state.matched_rounds, false)
}

#[derive(Debug)]
struct ReplayRound {
    status: ReplayRoundStatus,
    results: Vec<ReplayProbeResult>,
}

async fn run_replay_probe_round(
    target: &str,
    client_hello: &[u8],
    attempt: usize,
    probes: &[ProbeSpec],
) -> ReplayRound {
    if probes.is_empty() {
        return ReplayRound {
            status: ReplayRoundStatus::Valid,
            results: Vec::new(),
        };
    }

    let mut handles = Vec::with_capacity(probes.len());
    for (probe_index, probe) in probes.iter().cloned().enumerate() {
        let target = target.to_string();
        let client_hello = client_hello.to_vec();
        handles.push(tokio::spawn(async move {
            run_replay_probe_attempt(&target, &client_hello, attempt, probe_index, &probe).await
        }));
    }

    let mut results = Vec::with_capacity(probes.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(_) => {
                return ReplayRound {
                    status: ReplayRoundStatus::InternalError,
                    results: Vec::new(),
                };
            }
        }
    }

    if results
        .iter()
        .any(|result| result.connection_failed)
    {
        log::warn!(
            "TLS replay attempt={} discarded; connection failed in at least one probe",
            attempt
        );
        return ReplayRound {
            status: ReplayRoundStatus::ConnectionError,
            results,
        };
    }

    if !probe_round_has_signal(&results) {
        log::warn!(
            "TLS replay attempt={} discarded; all probes returned NONE",
            attempt
        );
        return ReplayRound {
            status: ReplayRoundStatus::NoSignal,
            results,
        };
    }

    ReplayRound {
        status: ReplayRoundStatus::Valid,
        results,
    }
}

async fn run_replay_probe_attempt(
    target: &str,
    client_hello: &[u8],
    attempt: usize,
    probe_index: usize,
    probe: &ProbeSpec,
) -> ReplayProbeResult {
    let mut result = ReplayProbeResult::default();
    result.got_response = replay_client_hello_to_server_once(
        target,
        client_hello,
        attempt,
        probe_index,
        probe,
        &mut result.appdata_close,
        &mut result.final_status,
    )
    .await;
    result.connection_failed = replay_status_is_connection_error(result.final_status);
    result
}

async fn replay_client_hello_to_server_once(
    target: &str,
    client_hello: &[u8],
    attempt: usize,
    probe_index: usize,
    probe: &ProbeSpec,
    appdata_close: &mut AppDataCloseProbe,
    status_out: &mut ReplayStatus,
) -> bool {
    *appdata_close = AppDataCloseProbe::default();
    *status_out = ReplayStatus::NoResponse;

    let mut stream = match timeout(REPLAY_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            *status_out = ReplayStatus::ConnectFailed;
            log::warn!(
                "TLS replay attempt={} probe={} server={} connect_failed error={}",
                attempt,
                probe_index + 1,
                target,
                err
            );
            return false;
        }
        Err(_) => {
            *status_out = ReplayStatus::ConnectFailed;
            log::warn!(
                "TLS replay attempt={} probe={} server={} connect_failed error=timed out",
                attempt,
                probe_index + 1,
                target
            );
            return false;
        }
    };

    if let Err(err) = stream.set_nodelay(true) {
        *status_out = ReplayStatus::SocketFailed;
        log::warn!(
            "TLS replay attempt={} server={} socket_failed error={}",
            attempt,
            target,
            err
        );
        return false;
    }

    if timeout(REPLAY_TIMEOUT, stream.write_all(client_hello))
        .await
        .is_err()
        || stream.write_all(&[]).await.is_err()
    {
        *status_out = ReplayStatus::SendFailed;
        log::warn!(
            "TLS replay attempt={} server={} failed=send_failed",
            attempt,
            target
        );
        return false;
    }

    let mut response = [0u8; 4096];
    let mut alert_data = Vec::new();
    let mut post_probe_data = Vec::new();
    let mut response_len = 0usize;
    let mut got_response = false;
    let mut appdata_started_at = None::<Instant>;

    loop {
        let read_budget = if appdata_close.sent {
            let Some(started_at) = appdata_started_at else {
                *status_out = ReplayStatus::RecvFailed;
                break;
            };
            let remaining = PROBE_OBSERVE_TIMEOUT.saturating_sub(started_at.elapsed());
            if remaining.is_zero() {
                appdata_close.status = ProbeStatus::Timeout;
                *status_out = ReplayStatus::Ok;
                break;
            }
            remaining
        } else {
            REPLAY_TIMEOUT
        };

        match timeout(read_budget, stream.read(&mut response)).await {
            Err(_) => {
                if appdata_close.sent {
                    appdata_close.status = ProbeStatus::Timeout;
                    *status_out = ReplayStatus::Ok;
                } else {
                    *status_out = ReplayStatus::Timeout;
                }
                break;
            }
            Ok(result) => match result {
                Ok(0) => {
                    *status_out = if got_response {
                        ReplayStatus::Ok
                    } else {
                        ReplayStatus::Closed
                    };
                    if appdata_close.sent && appdata_close.status == ProbeStatus::None {
                        appdata_close.status = ProbeStatus::Fin;
                    }
                    break;
                }
                Ok(n) => {
                    response_len += n;
                    append_with_cap(&mut alert_data, &response[..n], 65_536);
                    if buffer_contains_record_from_tail(&alert_data, 0x15, 2) {
                        appdata_close.status = ProbeStatus::Alert;
                        *status_out = ReplayStatus::Ok;
                        break;
                    }

                    if appdata_close.sent {
                        append_with_cap(&mut post_probe_data, &response[..n], 65_536);
                        if buffer_contains_record_from_tail(
                            &post_probe_data,
                            0x17,
                            TLS13_ENCRYPTED_ALERT_RECORD_LEN,
                        ) {
                            appdata_close.status = ProbeStatus::Alert;
                            *status_out = ReplayStatus::Ok;
                            break;
                        }
                    }

                    if !got_response {
                        got_response = true;
                        match timeout(REPLAY_TIMEOUT, stream.write_all(&probe.bytes)).await {
                            Ok(Ok(())) => {}
                            Ok(Err(err)) => {
                                *status_out = ReplayStatus::SendFailed;
                                log::error!(
                                    "TLS replay attempt={} probe={} server={} probe_send_failed bytes={} error={}",
                                    attempt,
                                    probe_index + 1,
                                    target,
                                    probe.bytes.len(),
                                    err
                                );
                                break;
                            }
                            Err(_) => {
                                *status_out = ReplayStatus::SendFailed;
                                log::error!(
                                    "TLS replay attempt={} probe={} server={} probe_send_failed bytes={} error=timed out",
                                    attempt,
                                    probe_index + 1,
                                    target,
                                    probe.bytes.len()
                                );
                                break;
                            }
                        }
                        appdata_close.sent = true;
                        appdata_started_at = Some(Instant::now());
                        log::info!(
                            "TLS replay attempt={} probe={} server={} sent probe bytes={}",
                            attempt,
                            probe_index + 1,
                            target,
                            probe.bytes.len()
                        );
                    }

                    if response_len >= 65_536 {
                        *status_out = ReplayStatus::BufferFull;
                        if appdata_close.sent {
                            appdata_close.status = ProbeStatus::Timeout;
                        }
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                    if appdata_close.sent {
                        appdata_close.status = ProbeStatus::Rst;
                        *status_out = ReplayStatus::Ok;
                    } else {
                        *status_out = ReplayStatus::RecvFailed;
                    }
                    log::error!(
                        "TLS replay attempt={} probe={} server={} recv_failed error={}",
                        attempt,
                        probe_index + 1,
                        target,
                        err
                    );
                    break;
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    *status_out = ReplayStatus::RecvFailed;
                    if appdata_close.sent {
                        appdata_close.status = ProbeStatus::Timeout;
                    }
                    log::error!(
                        "TLS replay attempt={} probe={} server={} recv_failed error={}",
                        attempt,
                        probe_index + 1,
                        target,
                        err
                    );
                    break;
                }
            },
        }
    }

    if got_response {
        log::info!(
            "TLS replay attempt={} probe={} server={} complete probe_status={} bytes={}",
            attempt,
            probe_index + 1,
            target,
            probe_status_name(replay_result_probe_status(&ReplayProbeResult {
                appdata_close: *appdata_close,
                got_response,
                connection_failed: false,
                final_status: *status_out,
            })),
            response_len
        );
    }

    got_response
}

fn load_default_probes() -> Vec<ProbeSpec> {
    DEFAULT_PROBE_LINES
        .iter()
        .filter_map(|line| parse_hex_line(line).ok())
        .map(|bytes| ProbeSpec { bytes })
        .collect()
}

fn load_probe_lines_from_file<P: AsRef<std::path::Path>>(path: P) -> std::io::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
        .map(ToOwned::to_owned)
        .collect())
}

fn load_probes(cli: &CliConfig) -> std::io::Result<Vec<ProbeSpec>> {
    let custom_probe_lines = collect_custom_probe_lines(cli)?;
    let mut probe_lines = match cli.probe_mode {
        ProbeMode::Replace => Vec::new(),
        ProbeMode::Append => DEFAULT_PROBE_LINES
            .iter()
            .map(|line| (*line).to_string())
            .collect(),
    };

    if custom_probe_lines.is_empty() {
        if matches!(cli.probe_mode, ProbeMode::Append) {
            return parse_probe_specs(&probe_lines);
        }
        let probes = load_default_probes();
        if probes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no probes were loaded",
            ));
        }
        return Ok(probes);
    }

    probe_lines.extend(custom_probe_lines);
    parse_probe_specs(&probe_lines)
}

fn collect_custom_probe_lines(cli: &CliConfig) -> std::io::Result<Vec<String>> {
    let mut lines = cli.probe_lines.clone();
    for path in &cli.probe_files {
        lines.extend(load_probe_lines_from_file(path)?);
    }
    Ok(lines)
}

fn parse_probe_specs(lines: &[String]) -> std::io::Result<Vec<ProbeSpec>> {
    use std::io::{Error, ErrorKind::InvalidInput};
    let probes: Result<Vec<_>, _> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            parse_hex_line(line.as_str())
                .map(|bytes| ProbeSpec { bytes })
                .map_err(|_| {
                    Error::new(
                        InvalidInput,
                        format!("invalid probe hex at entry {}: {}", index + 1, line),
                    )
                })
        })
        .collect();

    let probes = probes?;
    if probes.is_empty() {
        return Err(Error::new(InvalidInput, "no probes were loaded"));
    }

    Ok(probes)
}

fn parse_hex_line(line: &str) -> Result<Vec<u8>, ()> {
    let filtered: Vec<char> = line
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return Err(());
    }

    let mut out = Vec::with_capacity(filtered.len() / 2);
    for pair in filtered.chunks(2) {
        let hi = pair[0].to_digit(16).ok_or(())?;
        let lo = pair[1].to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn append_with_cap(dst: &mut Vec<u8>, src: &[u8], cap: usize) {
    if dst.len() >= cap {
        return;
    }
    let room = cap - dst.len();
    let copy_len = src.len().min(room);
    dst.extend_from_slice(&src[..copy_len]);
}

fn buffer_contains_record_from_tail(data: &[u8], record_type: u8, record_len: u16) -> bool {
    let full_len = 5 + record_len as usize;
    if data.len() < full_len {
        return false;
    }

    for pos in (0..=data.len() - full_len).rev() {
        if data[pos] == record_type
            && data[pos + 1] == 0x03
            && data[pos + 2] == 0x03
            && read_be16(&data[pos + 3..pos + 5]) == record_len
        {
            return true;
        }
    }

    false
}

fn replay_status_is_connection_error(status: ReplayStatus) -> bool {
    matches!(
        status,
        ReplayStatus::SocketFailed
            | ReplayStatus::NonblockFailed
            | ReplayStatus::BindFailed
            | ReplayStatus::ConnectFailed
    )
}

fn replay_result_probe_status(result: &ReplayProbeResult) -> ProbeStatus {
    if !result.got_response || result.appdata_close.status == ProbeStatus::None {
        ProbeStatus::None
    } else {
        result.appdata_close.status
    }
}

fn probe_rounds_match(a: &[ReplayProbeResult], b: &[ReplayProbeResult]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(left, right)| {
                replay_result_probe_status(left) == replay_result_probe_status(right)
            })
}

fn probe_round_has_signal(results: &[ReplayProbeResult]) -> bool {
    results
        .iter()
        .any(|result| replay_result_probe_status(result) != ProbeStatus::None)
}

fn report_filter_matches_a_fingerprint(results: &[ReplayProbeResult]) -> bool {
    let expected = [
        ProbeStatus::Timeout,
        ProbeStatus::Alert,
        ProbeStatus::Alert,
        ProbeStatus::Alert,
        ProbeStatus::Alert,
        ProbeStatus::Alert,
        ProbeStatus::Alert,
    ];

    results.len() == expected.len()
        && results
            .iter()
            .zip(expected.iter())
            .all(|(result, expected)| replay_result_probe_status(result) == *expected)
}

fn replay_probe_matches_alarm_condition(a: &[ReplayProbeResult], b: &[ReplayProbeResult]) -> bool {
    !probe_rounds_match(a, b) && report_filter_matches_a_fingerprint(a)
}

fn format_probe_status_list(results: &[ReplayProbeResult]) -> String {
    results
        .iter()
        .map(|result| probe_status_name(replay_result_probe_status(result)).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn probe_status_name(status: ProbeStatus) -> &'static str {
    match status {
        ProbeStatus::Alert => "ALERT",
        ProbeStatus::Fin => "FIN",
        ProbeStatus::Rst => "RST",
        ProbeStatus::Timeout => "TO",
        ProbeStatus::None => "NONE",
    }
}

fn replay_round_status_name(status: ReplayRoundStatus) -> &'static str {
    match status {
        ReplayRoundStatus::Valid => "valid",
        ReplayRoundStatus::ConnectionError => "connection_error",
        ReplayRoundStatus::NoSignal => "no_signal",
        ReplayRoundStatus::InternalError => "internal_error",
    }
}

fn format_client_hello(target: &str, info: &ClientHelloInfo) -> String {
    let mut parts = Vec::new();
    parts.push(format!(
        "TLS ClientHello target={} record_version=0x{:02x}{:02x} legacy_version=0x{:04x} cipher_suites={} extensions={}",
        target,
        info.record_version_major,
        info.record_version_minor,
        info.legacy_version,
        info.cipher_suite_count,
        info.extension_count
    ));
    if !info.sni.is_empty() {
        parts.push(format!("sni={}", info.sni));
    }
    if !info.alpn.is_empty() {
        parts.push(format!("alpn={}", info.alpn));
    }
    if !info.supported_versions.is_empty() {
        parts.push(format!("supported_versions={}", info.supported_versions));
    }
    parts.join(" ")
}

fn format_server_hello(target: &str, info: &ServerHelloInfo) -> String {
    format!(
        "TLS ServerHello target={} selected_version=0x{:04x}",
        target, info.selected_version
    )
}

fn parse_client_hello(data: &[u8]) -> Option<(ClientHelloInfo, usize)> {
    let (record, record_len) = find_tls_handshake_record(data, 0x01)?;

    if record_len < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01 {
        return None;
    }

    let tls_record_len = read_be16(&record[3..5]);
    let hs_len = read_be24(&record[6..9]);
    if (tls_record_len as usize) + 5 > record_len
        || (hs_len as usize) + 9 > (tls_record_len as usize) + 5
    {
        return None;
    }

    let body = &record[9..9 + hs_len as usize];
    if body.len() < 38 {
        return None;
    }

    let legacy_version = read_be16(&body[0..2]);
    let mut off = 2 + 32;
    let session_id_len = *body.get(off)? as usize;
    off += 1;
    if off + session_id_len + 2 > body.len() {
        return None;
    }
    off += session_id_len;

    let cipher_len = read_be16(&body[off..off + 2]) as usize;
    off += 2;
    if off + cipher_len + 1 > body.len() {
        return None;
    }
    off += cipher_len;

    let compression_len = *body.get(off)? as usize;
    off += 1;
    if off + compression_len > body.len() {
        return None;
    }
    off += compression_len;

    let mut info = ClientHelloInfo {
        legacy_version,
        record_version_major: record[1],
        record_version_minor: record[2],
        cipher_suite_count: cipher_len / 2,
        ..Default::default()
    };

    if off + 2 <= body.len() {
        let extensions_len = read_be16(&body[off..off + 2]) as usize;
        off += 2;
        if off + extensions_len <= body.len() {
            let (sni, alpn, versions, extension_count) =
                parse_extensions(&body[off..off + extensions_len]);
            info.sni = sni;
            info.alpn = alpn;
            info.supported_versions = versions;
            info.extension_count = extension_count;
        }
    }

    Some((info, record_len))
}

fn parse_server_hello(data: &[u8]) -> Option<ServerHelloInfo> {
    let (record, record_len) = find_tls_handshake_record(data, 0x02)?;

    if record_len < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x02 {
        return None;
    }

    let tls_record_len = read_be16(&record[3..5]);
    let hs_len = read_be24(&record[6..9]);
    if (tls_record_len as usize) + 5 > record_len
        || (hs_len as usize) + 9 > (tls_record_len as usize) + 5
    {
        return None;
    }

    let body = &record[9..9 + hs_len as usize];
    if body.len() < 38 {
        return None;
    }

    let mut selected_version = read_be16(&body[0..2]);
    let mut off = 2 + 32;
    let session_id_len = *body.get(off)? as usize;
    off += 1;
    if off + session_id_len + 3 > body.len() {
        return None;
    }
    off += session_id_len;
    off += 2;
    off += 1;

    if off + 2 <= body.len() {
        let extensions_len = read_be16(&body[off..off + 2]) as usize;
        off += 2;
        if off + extensions_len > body.len() {
            return None;
        }

        let mut ext_off = off;
        let end = off + extensions_len;
        while ext_off + 4 <= end {
            let ext_type = read_be16(&body[ext_off..ext_off + 2]);
            let ext_len = read_be16(&body[ext_off + 2..ext_off + 4]) as usize;
            ext_off += 4;
            if ext_off + ext_len > end {
                return None;
            }
            if ext_type == 43 && ext_len == 2 {
                selected_version = read_be16(&body[ext_off..ext_off + 2]);
                break;
            }
            ext_off += ext_len;
        }
    }

    Some(ServerHelloInfo { selected_version })
}

fn find_tls_handshake_record(data: &[u8], handshake_type: u8) -> Option<(&[u8], usize)> {
    if data.len() < 9 {
        return None;
    }

    for off in 0..=data.len().saturating_sub(9) {
        if data[off] != 0x16 || data[off + 1] != 0x03 {
            continue;
        }
        let tls_len = read_be16(&data[off + 3..off + 5]) as usize;
        if tls_len < 4 || off + 5 + tls_len > data.len() {
            continue;
        }
        if data[off + 5] != handshake_type {
            continue;
        }
        let record_len = 5 + tls_len;
        return Some((&data[off..off + record_len], record_len));
    }

    None
}

fn parse_extensions(exts: &[u8]) -> (String, String, String, usize) {
    let mut sni = String::new();
    let mut alpn = String::new();
    let mut versions = String::new();
    let mut extension_count = 0;
    let mut off = 0;

    while off + 4 <= exts.len() {
        let ext_type = read_be16(&exts[off..off + 2]);
        let ext_len = read_be16(&exts[off + 2..off + 4]) as usize;
        off += 4;
        if off + ext_len > exts.len() {
            break;
        }

        let ext = &exts[off..off + ext_len];
        match ext_type {
            0 if ext_len >= 5 => {
                let list_len = read_be16(&ext[0..2]) as usize;
                let mut pos = 2;
                while pos + 3 <= ext_len && pos < list_len + 2 {
                    let name_type = ext[pos];
                    let name_len = read_be16(&ext[pos + 1..pos + 3]) as usize;
                    pos += 3;
                    if pos + name_len > ext_len {
                        break;
                    }
                    if name_type == 0 && sni.is_empty() {
                        sni = printable_string(&ext[pos..pos + name_len]);
                        break;
                    }
                    pos += name_len;
                }
            }
            16 if ext_len >= 3 => {
                let list_len = read_be16(&ext[0..2]) as usize;
                let mut pos = 2;
                while pos < ext_len && pos < list_len + 2 {
                    let name_len = ext[pos] as usize;
                    pos += 1;
                    if pos + name_len > ext_len {
                        break;
                    }
                    if !alpn.is_empty() {
                        alpn.push(',');
                    }
                    alpn.push_str(&printable_string(&ext[pos..pos + name_len]));
                    pos += name_len;
                }
            }
            43 if ext_len >= 1 => {
                let list_len = ext[0] as usize;
                if list_len < ext_len {
                    let mut pos = 1;
                    while pos + 1 < 1 + list_len && pos + 1 < ext_len {
                        if !versions.is_empty() {
                            versions.push(',');
                        }
                        versions.push_str(&format!("0x{:02x}{:02x}", ext[pos], ext[pos + 1]));
                        pos += 2;
                    }
                }
            }
            _ => {}
        }

        off += ext_len;
        extension_count += 1;
    }

    (sni, alpn, versions, extension_count)
}

fn printable_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn randomize_client_hello_legacy_session_id(
    record: &mut [u8],
    session_id_len_out: &mut u8,
    before_hash_out: &mut u32,
    after_hash_out: &mut u32,
) -> bool {
    *session_id_len_out = 0;
    *before_hash_out = 0;
    *after_hash_out = 0;

    if record.len() < 9 || record[0] != 0x16 || record[1] != 0x03 || record[5] != 0x01 {
        return false;
    }

    let tls_record_len = read_be16(&record[3..5]) as usize;
    let hs_len = read_be24(&record[6..9]) as usize;
    if tls_record_len + 5 > record.len() || hs_len + 9 > tls_record_len + 5 {
        return false;
    }

    let body = &mut record[9..9 + hs_len];
    if body.len() < 2 + 32 + 1 {
        return false;
    }

    let mut off = 2 + 32;
    let session_id_len = body[off] as usize;
    off += 1;
    if session_id_len == 0 || off + session_id_len > body.len() {
        return false;
    }

    *before_hash_out = hash_bytes32(&body[off..off + session_id_len]);
    fill_random_bytes(&mut body[off..off + session_id_len]);
    *after_hash_out = hash_bytes32(&body[off..off + session_id_len]);
    *session_id_len_out = session_id_len as u8;
    true
}

async fn read_request(
    stream: OwnedReadHalf,
) -> std::io::Result<(String, String, TokioBufReader<OwnedReadHalf>)> {
    let mut reader = TokioBufReader::new(stream);

    let mut first_line = String::new();
    if reader
        .read_line(&mut first_line)
        .await?
        == 0
    {
        use std::io::ErrorKind::UnexpectedEof;
        return Err(std::io::Error::new(UnexpectedEof, "empty request"));
    }

    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .unwrap_or_default()
        .to_string();
    let target = parts
        .next()
        .unwrap_or_default()
        .to_string();

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok((method, target, reader))
}

fn read_be16(bytes: &[u8]) -> u16 {
    ((bytes[0] as u16) << 8) | (bytes[1] as u16)
}

fn read_be24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

fn fill_random_bytes(dst: &mut [u8]) {
    let mut x = timestamp_seed() ^ ((dst.as_ptr() as usize) as u64);
    if x == 0 {
        x = 0x9e37_79b9_7f4a_7c15;
    }

    for byte in dst.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *byte = (x & 0xff) as u8;
    }
}

fn timestamp_seed() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() ^ u64::from(duration.subsec_nanos()),
        Err(_) => 0x1234_5678_9abc_def0,
    }
}

fn hash_bytes32(value: &[u8]) -> u32 {
    let mut hash = 2166136261u32;
    for &byte in value {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16777619);
    }
    hash
}
