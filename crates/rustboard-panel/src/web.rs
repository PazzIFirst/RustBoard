//! 静态资源服务：读盘、SPA 回退、路径穿越防护与 MIME 映射。
//!
//! 查找顺序：`static_dir` → `./web/dist` → `/usr/share/rustboard/web`。
//! 找不到 `index.html` 时所有页面请求返回可读的 503，而不是 panic。
//! `/api/*` 由路由层单独处理，绝不会回退到 index.html。

use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Result};
use axum::body::Body;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;

/// 未配置 `static_dir` 时依次尝试的目录。
const DEFAULT_STATIC_DIRS: [&str; 2] = ["./web/dist", "/usr/share/rustboard/web"];

/// 已解析的静态站点根目录。
#[derive(Debug, Clone)]
pub struct StaticFiles {
    root: PathBuf,
    index: PathBuf,
}

enum Lookup {
    File(PathBuf),
    Spa,
    MissingAsset,
    Forbidden,
}

impl StaticFiles {
    /// 按配置与默认目录查找可用的前端构建产物。
    ///
    /// - 显式配置了 `static_dir`：只认该目录，不可用就返回错误，**绝不静默回退**；
    /// - 未配置：才依次尝试 `./web/dist` 与 `/usr/share/rustboard/web`。
    pub fn discover(configured: &str) -> Result<Option<Self>> {
        let configured = configured.trim();
        if !configured.is_empty() {
            let Some(files) = Self::from_root(configured) else {
                bail!(
                    "static_dir 不可用（目录不存在、缺少 index.html，或 index.html 逃逸出该目录）: \
                     {configured}"
                );
            };
            tracing::info!(dir = %files.root.display(), "静态资源目录已就绪");
            return Ok(Some(files));
        }

        for dir in DEFAULT_STATIC_DIRS {
            if let Some(files) = Self::from_root(dir) {
                tracing::info!(dir = %files.root.display(), "静态资源目录已就绪");
                return Ok(Some(files));
            }
            tracing::debug!(dir = %dir, "默认静态资源目录不可用（缺少 index.html）");
        }
        Ok(None)
    }

    /// 从确定的根目录构造；`index.html` 必须是根目录内的普通文件。
    pub fn from_root(root: impl AsRef<Path>) -> Option<Self> {
        let root = std::fs::canonicalize(root.as_ref()).ok()?;
        let index = std::fs::canonicalize(root.join("index.html")).ok()?;
        if !index.starts_with(&root) || !index.is_file() {
            tracing::warn!(root = %root.display(), "index.html 逃逸出静态目录，拒绝使用");
            return None;
        }
        Some(Self { root, index })
    }

    /// 处理一次静态资源请求。`request_path` 是已解码、无前导斜杠的相对路径。
    pub async fn serve(&self, request_path: &str) -> Response {
        match self.lookup(request_path) {
            Lookup::File(path) => self.serve_file(&path, request_path).await,
            Lookup::Spa => self.serve_index().await,
            Lookup::MissingAsset => text_response(
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                "404 Not Found",
                "no-store",
            ),
            Lookup::Forbidden => text_response(
                StatusCode::FORBIDDEN,
                "text/plain; charset=utf-8",
                "403 Forbidden",
                "no-store",
            ),
        }
    }

    fn lookup(&self, request_path: &str) -> Lookup {
        if request_path.is_empty() {
            return Lookup::Spa;
        }
        let relative = Path::new(request_path);
        if relative.is_absolute() {
            return Lookup::Forbidden;
        }
        let mut candidate = self.root.clone();
        for component in relative.components() {
            match component {
                Component::Normal(segment) => {
                    // 反斜杠在 Linux 是合法文件名字符，但接受它会让 Windows 部署出现歧义。
                    if segment.to_string_lossy().contains('\\') {
                        return Lookup::Forbidden;
                    }
                    candidate.push(segment);
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Lookup::Forbidden
                }
            }
        }

        match std::fs::metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => match std::fs::canonicalize(&candidate) {
                Ok(path) if path.starts_with(&self.root) => Lookup::File(path),
                Ok(_) => Lookup::Forbidden,
                Err(_) => Lookup::MissingAsset,
            },
            Ok(metadata) if metadata.is_dir() => {
                let index = candidate.join("index.html");
                match std::fs::canonicalize(&index) {
                    Ok(path) if path.starts_with(&self.root) && path.is_file() => {
                        Lookup::File(path)
                    }
                    _ => Lookup::Spa,
                }
            }
            Ok(_) => Lookup::MissingAsset,
            Err(_) => {
                if looks_like_asset(request_path) {
                    Lookup::MissingAsset
                } else {
                    Lookup::Spa
                }
            }
        }
    }

    async fn serve_file(&self, path: &Path, request_path: &str) -> Response {
        match read_file(path).await {
            Ok(bytes) => {
                let cache = cache_control_for(request_path);
                response_with(StatusCode::OK, mime_for(path), bytes, cache)
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), error = %error, "读取静态资源失败");
                text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "text/plain; charset=utf-8",
                    "500 Internal Server Error",
                    "no-store",
                )
            }
        }
    }

    async fn serve_index(&self) -> Response {
        match read_file(&self.index).await {
            Ok(bytes) => response_with(
                StatusCode::OK,
                "text/html; charset=utf-8",
                bytes,
                "no-cache",
            ),
            Err(error) => {
                tracing::error!(error = %error, "读取 index.html 失败");
                missing_site_response()
            }
        }
    }
}

/// 读盘放到阻塞线程池，避免大文件阻塞 async 执行器。
async fn read_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read(path))
        .await
        .map_err(std::io::Error::other)?
}

/// 缺少前端构建产物时的可读提示。
pub fn missing_site_response() -> Response {
    let body = "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\
         <title>RustBoard 面板</title></head><body style=\"background:#0b0e14;color:#c9d1d9;\
         font:14px/1.7 ui-sans-serif,system-ui,sans-serif;padding:40px\">\
         <h1>前端资源未就绪</h1>\
         <p>没有找到 RustBoard 前端构建产物（<code>index.html</code>）。</p>\
         <p>请在仓库根目录执行 <code>pnpm --dir web install &amp;&amp; pnpm --dir web build</code>，\
         或在 <code>panel.toml</code> 里用 <code>static_dir</code> 指向已构建的目录，\
         或安装到 <code>/usr/share/rustboard/web</code>。</p>\
         <p>健康检查：<a style=\"color:#58a6ff\" href=\"/healthz\">/healthz</a></p>\
         </body></html>";
    text_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "text/html; charset=utf-8",
        body,
        "no-store",
    )
}

/// 路径看起来像一个静态资源（最后一段带扩展名）时，缺失应 404 而不是回退 HTML。
fn looks_like_asset(request_path: &str) -> bool {
    request_path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.contains('.') && name != "." && name != "..")
}

/// 只映射方案列出的类型，未知后缀回退 octet-stream。
pub fn mime_for(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

fn cache_control_for(request_path: &str) -> &'static str {
    // Vite 产物在 assets/ 下带内容哈希，可以长缓存；入口 HTML 必须每次校验。
    if request_path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn response_with(
    status: StatusCode,
    content_type: &'static str,
    body: Vec<u8>,
    cache_control: &'static str,
) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn text_response(
    status: StatusCode,
    content_type: &'static str,
    body: &str,
    cache_control: &'static str,
) -> Response {
    response_with(
        status,
        content_type,
        body.as_bytes().to_vec(),
        cache_control,
    )
}

/// M5 打包时用 include_dir 内嵌前端；本阶段只预留 feature，不启用。
#[cfg(feature = "embedded-web")]
#[allow(dead_code)]
static EMBEDDED_WEB: include_dir::Dir<'static> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/../../web/dist");

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempSite {
        dir: PathBuf,
    }

    impl TempSite {
        fn new() -> Self {
            let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "rustboard-panel-web-{}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("assets")).unwrap();
            std::fs::write(
                dir.join("index.html"),
                "<!doctype html><title>RustBoard</title><div id=root></div>",
            )
            .unwrap();
            std::fs::write(dir.join("assets/app.js"), "console.log('ok')").unwrap();
            std::fs::write(dir.join("assets/app.css"), "body{color:#fff}").unwrap();
            std::fs::write(dir.join("favicon.svg"), "<svg></svg>").unwrap();
            std::fs::write(dir.join("data.json"), "{}").unwrap();
            Self { dir }
        }

        fn files(&self) -> StaticFiles {
            StaticFiles::from_root(&self.dir).expect("测试站点应可加载")
        }
    }

    impl Drop for TempSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn body_text(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn serves_index_and_spa_fallback() {
        let site = TempSite::new();
        let files = site.files();

        let response = files.serve("").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache"
        );
        assert!(body_text(response).await.contains("<!doctype html>"));

        let response = files.serve("agents/hub-self").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("<!doctype html>"));
    }

    #[tokio::test]
    async fn serves_assets_with_mime_and_long_cache() {
        let site = TempSite::new();
        let files = site.files();

        let response = files.serve("assets/app.js").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        assert_eq!(body_text(response).await, "console.log('ok')");

        assert_eq!(
            files.serve("assets/app.css").await.headers()[header::CONTENT_TYPE],
            "text/css; charset=utf-8"
        );
        assert_eq!(
            files.serve("favicon.svg").await.headers()[header::CONTENT_TYPE],
            "image/svg+xml"
        );
        assert_eq!(
            files.serve("data.json").await.headers()[header::CONTENT_TYPE],
            "application/json"
        );
    }

    #[tokio::test]
    async fn missing_asset_is_404_not_spa() {
        let site = TempSite::new();
        let files = site.files();
        let response = files.serve("assets/missing.js").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!body_text(response).await.contains("<!doctype html>"));
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let site = TempSite::new();
        let files = site.files();
        for path in [
            "../etc/passwd",
            "..",
            "agents/../../etc/passwd",
            "/etc/passwd",
            "a\\..\\b",
        ] {
            let response = files.serve(path).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "路径 {path} 应被拒绝"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let site = TempSite::new();
        symlink("/etc/passwd", site.dir.join("leak.txt")).unwrap();
        let files = site.files();
        let response = files.serve("leak.txt").await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!body_text(response).await.contains("root:"));
    }

    #[tokio::test]
    async fn missing_index_returns_503_hint() {
        let site = TempSite::new();
        std::fs::remove_file(site.dir.join("index.html")).unwrap();
        assert!(StaticFiles::from_root(&site.dir).is_none());

        let response = missing_site_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_text(response).await;
        assert!(body.contains("前端资源未就绪"));
        assert!(body.contains("pnpm --dir web"));
    }

    #[test]
    fn explicit_static_dir_never_falls_back() {
        let site = TempSite::new();
        let files = StaticFiles::discover(site.dir.to_str().unwrap())
            .expect("有效的显式目录必须能加载")
            .expect("有效的显式目录必须返回文件集");
        assert_eq!(files.root, std::fs::canonicalize(&site.dir).unwrap());

        // 目录存在但缺 index.html：必须报错，而不是回退到默认的 web/dist。
        let empty = site.dir.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let error = StaticFiles::discover(empty.to_str().unwrap())
            .expect_err("缺少 index.html 的显式目录必须报错");
        assert!(error.to_string().contains("static_dir"));

        let missing = site.dir.join("does-not-exist");
        let error =
            StaticFiles::discover(missing.to_str().unwrap()).expect_err("不存在的显式目录必须报错");
        assert!(error.to_string().contains("static_dir"));
    }

    #[test]
    fn maps_mime_by_extension() {
        assert_eq!(mime_for(Path::new("a.html")), "text/html; charset=utf-8");
        assert_eq!(
            mime_for(Path::new("A.JS")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(mime_for(Path::new("x.woff2")), "font/woff2");
        assert_eq!(mime_for(Path::new("x.ico")), "image/x-icon");
        assert_eq!(mime_for(Path::new("x.bin")), "application/octet-stream");
        assert_eq!(mime_for(Path::new("noext")), "application/octet-stream");
    }
}
