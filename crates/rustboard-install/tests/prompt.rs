//! Prompt 非交互行为（集成层）。

use std::io::IsTerminal;

use rustboard_install::Prompt;

#[test]
fn assume_yes_uses_defaults_without_stdin() {
    let prompt = Prompt::new(true);
    assert!(!prompt.confirm("继续吗", false).unwrap());
    assert!(prompt.confirm("继续吗", true).unwrap());
    assert_eq!(prompt.text("名称", "默认名").unwrap(), "默认名");
}

#[test]
fn non_interactive_prompt_errors_without_yes() {
    if std::io::stdin().is_terminal() {
        // 测试运行在真实终端时无法制造非交互 stdin，交互分支由单元测试覆盖。
        return;
    }
    let prompt = Prompt::new(false);
    assert!(prompt.confirm("继续吗", true).is_err());
    assert!(prompt.text("名称", "默认名").is_err());
}
