//! RustBoard 面板。
//!
//! M1 阶段只提供占位页与健康检查；M2 接入真实图表。

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use clap::{Parser, Subcommand};
use rustboard_common::config::PanelConfig;
use rustboard_common::DEFAULT_PANEL_CONFIG;

#[derive(Parser)]
#[command(name = "rustboard-panel", version, about = "RustBoard 面板")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        hub: Option<String>,
    },
    Init {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rustboard_panel=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match Cli::parse().cmd {
        Cmd::Init { config, listen, hub, force } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
            if path.exists() && !force {
                bail!("{} 已存在，使用 --force 覆盖", path.display());
            }
            let mut cfg = PanelConfig::default();
            if let Some(l) = listen {
                cfg.listen = l;
            }
            if let Some(h) = hub {
                cfg.hub_url = h;
            }
            cfg.save(&path)?;
            println!("已写入配置: {}", path.display());
            println!("面板监听: {}", cfg.listen);
            println!("hub API: {}", cfg.hub_url);
            Ok(())
        }
        Cmd::Run { config, listen, hub } => {
            let mut cfg = PanelConfig::default();
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
            if path.exists() {
                cfg = PanelConfig::load(&path)
                    .with_context(|| format!("读取配置失败: {}", path.display()))?;
            }
            if let Some(l) = listen {
                cfg.listen = l;
            }
            if let Some(h) = hub {
                cfg.hub_url = h;
            }
            run(cfg)
        }
    }
}

fn run(cfg: PanelConfig) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async move {
        let app = Router::new()
            .route("/", get(index))
            .route("/healthz", get(|| async { "ok" }));
        let listener = tokio::net::TcpListener::bind(&cfg.listen)
            .await
            .with_context(|| format!("监听 {} 失败", cfg.listen))?;
        tracing::info!(listen = %cfg.listen, hub = %cfg.hub_url, "面板已启动");
        axum::serve(listener, app).await?;
        Ok(())
    })
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RustBoard</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         background:#0b0e14; color:#c9d1d9;
         font:14px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial; }
  .card { max-width:640px; padding:40px; border:1px solid #1f2430; border-radius:14px;
          background:#11151d; box-shadow:0 20px 60px rgba(0,0,0,.5); }
  h1 { margin:0 0 8px; font-size:22px; letter-spacing:.5px; color:#e6edf3; }
  .tag { display:inline-block; margin-bottom:20px; padding:2px 8px; border-radius:999px;
         background:#1f6feb22; color:#58a6ff; font-size:12px; }
  code { background:#0b0e14; padding:2px 6px; border-radius:5px; color:#79c0ff; }
  a { color:#58a6ff; }
  ul { padding-left:18px; }
  .muted { color:#6e7681; }
</style>
</head>
<body>
  <main class="card">
    <span class="tag">M1 · 骨架</span>
    <h1>RustBoard 面板</h1>
    <p>服务已经跑起来了。前端工程（React + Vite）会在 M2 接入，届时这里会变成真正的 Dashboard。</p>
    <ul>
      <li>hub 管理 API：<code>/api/v1/agents</code>、<code>/api/v1/series</code></li>
      <li>健康检查：<a href="/healthz">/healthz</a></li>
    </ul>
    <p class="muted">采集 → 缓冲 → 上报 → 存储 的链路已在 M1 打通。</p>
  </main>
</body>
</html>
"#;
