//! 安装交互提示。
//!
//! 非交互（stdin 非 TTY）且未 `--yes` 时直接报错：安装器不能把空输入当成默认
//! 值，否则 CI / 管道场景会在无人确认的情况下改系统。ANSI 颜色只在 TTY 输出。

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::{bail, Context, Result};

/// 交互提示器。
pub struct Prompt {
    assume_yes: bool,
    stdin_is_tty: bool,
}

impl Prompt {
    /// 创建提示器；是否 TTY 由当前 stdin 决定。
    pub fn new(assume_yes: bool) -> Self {
        Self {
            assume_yes,
            stdin_is_tty: io::stdin().is_terminal(),
        }
    }

    /// 是非题。`assume_yes` 时返回 `default`；非 TTY 且未 `--yes` 时报错。
    pub fn confirm(&self, question: &str, default: bool) -> Result<bool> {
        if self.assume_yes {
            return Ok(default);
        }
        if !self.stdin_is_tty {
            bail!("当前 stdin 不是交互终端，无法确认「{question}」；请使用 --yes 或显式参数");
        }

        let hint = if default { "Y/n" } else { "y/N" };
        self.print_prompt(&format!("{question} [{hint}]: "))?;
        let line = read_line()?;
        interpret_confirm_answer(&line, default)
    }

    /// 文本输入。`assume_yes` 时返回 `default`；非 TTY 且未 `--yes` 时报错。
    pub fn text(&self, question: &str, default: &str) -> Result<String> {
        if self.assume_yes {
            return Ok(default.to_string());
        }
        if !self.stdin_is_tty {
            bail!("当前 stdin 不是交互终端，无法输入「{question}」；请使用 --yes 或显式参数");
        }

        let shown_default = if default.is_empty() {
            String::new()
        } else {
            format!(" [{default}]")
        };
        self.print_prompt(&format!("{question}{shown_default}: "))?;
        let line = read_line()?;
        let answer = line.trim();
        if answer.is_empty() {
            return Ok(default.to_string());
        }
        Ok(answer.to_string())
    }

    /// 只在 TTY 下加 ANSI 颜色。
    fn print_prompt(&self, text: &str) -> Result<()> {
        let rendered = render_prompt(text, self.stdin_is_tty);
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(rendered.as_bytes())
            .and_then(|_| stdout.flush())
            .context("输出交互提示失败")
    }
}

/// 解析是非题回答；空输入返回 `default`。
///
/// 显式支持 `y/yes/true` 与 `n/no/false`（大小写不敏感，允许前后空白），
/// 其他输入直接报错而不是猜测。安装流程必须使用返回值；`false` 表示取消，
/// 调用方不得继续任何写入 / 加锁 / 证书 / unit 操作。
fn interpret_confirm_answer(answer: &str, default: bool) -> Result<bool> {
    let answer = answer.trim().to_ascii_lowercase();
    if answer.is_empty() {
        return Ok(default);
    }
    match answer.as_str() {
        "y" | "yes" | "true" => Ok(true),
        "n" | "no" | "false" => Ok(false),
        other => bail!("无法识别的回答 {other:?}，请输入 y 或 n"),
    }
}

/// 渲染提示文本：TTY 才加 ANSI，管道/重定向场景保持纯文本。
fn render_prompt(text: &str, stdin_is_tty: bool) -> String {
    if stdin_is_tty {
        format!("\x1b[1;36m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

fn read_line() -> Result<String> {
    let mut line = String::new();
    let read = io::stdin()
        .lock()
        .read_line(&mut line)
        .context("读取交互输入失败")?;
    if read == 0 {
        bail!("stdin 已关闭（EOF），无法读取交互输入");
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_interactive(assume_yes: bool) -> Prompt {
        Prompt {
            assume_yes,
            stdin_is_tty: false,
        }
    }

    #[test]
    fn non_tty_without_yes_errors() {
        let prompt = non_interactive(false);
        assert!(prompt.confirm("继续吗", true).is_err());
        assert!(prompt.text("名称", "默认名").is_err());
    }

    #[test]
    fn assume_yes_uses_defaults_without_reading() {
        let prompt = non_interactive(true);
        assert!(!prompt.confirm("继续吗", false).unwrap());
        assert!(prompt.confirm("继续吗", true).unwrap());
        assert_eq!(prompt.text("名称", "默认名").unwrap(), "默认名");
        assert_eq!(prompt.text("空默认", "").unwrap(), "");
    }

    #[test]
    fn confirm_answers_cover_yes_no_false_and_empty() {
        // 安装确认必须识别这些回答；`false` 是取消，调用方不能丢弃返回值。
        for answer in ["y", "Y", "yes", "YES", "true", " true \n"] {
            assert!(
                interpret_confirm_answer(answer, false).unwrap(),
                "{answer:?}"
            );
        }
        for answer in ["n", "N", "no", "NO", "false", " false \n"] {
            assert!(
                !interpret_confirm_answer(answer, true).unwrap(),
                "{answer:?}"
            );
        }
        // 空输入 / 纯空白走默认值。
        assert!(!interpret_confirm_answer("", false).unwrap());
        assert!(interpret_confirm_answer(" \t\r\n", true).unwrap());
        assert!(interpret_confirm_answer("", true).unwrap());
        assert!(!interpret_confirm_answer("  \n", false).unwrap());
        // 无法识别时 fail-closed，不能当作 yes。
        for answer in ["", "maybe", "0", "1"] {
            if answer.is_empty() {
                continue;
            }
            assert!(
                interpret_confirm_answer(answer, true).is_err(),
                "{answer:?} 必须被拒绝"
            );
        }
    }

    #[test]
    fn ansi_only_for_tty() {
        assert!(!render_prompt("问题 [y/N]: ", false).contains('\x1b'));
        assert!(render_prompt("问题 [y/N]: ", true).contains('\x1b'));
    }
}
