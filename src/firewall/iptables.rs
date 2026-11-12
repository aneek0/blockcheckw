//! Iptables-legacy бэкенд firewall-слоя — для Android-ядер без CONFIG_NF_TABLES.
//!
//! Включается `BCW_FIREWALL=iptables`. Правила НЕ генерируются здесь заново:
//! их единственный источник — nft-строки из `firewall/nftables.rs`; этот модуль
//! только переводит их в документ `iptables-restore` либо в толерантные CLI-удаления.
//!
//! Соответствие сущностей (проверено на устройстве, iptables v1.8.11 legacy):
//!
//! | nft                          | iptables                                        |
//! |------------------------------|-------------------------------------------------|
//! | таблица `inet <name>`        | цепочки `<name>_postnat`/`<name>_prenat` (mangle), `<name>_predefrag` (raw) |
//! | `add table` + хуки           | `:chain - [0:0]` + прыжки из встроенных цепочек |
//! | `delete table`               | CLI `-D` прыжков + `-X` цепочек (толерантно)    |
//! | `flush chain`                | повторный `:chain - [0:0]` (флашит правила)     |
//!
//! Почему удаление — CLI, а не restore: `-D`/`-X` отсутствующего в
//! restore-документе валит ВЕСЬ батч (`line N failed`), а `-A` прыжка при
//! повторном prepare ДУБЛИРУЕТ его. Идемпотентность здесь важнее одного
//! лишнего процесса: CLI-`iptables` сам игнорирует «чего нет» через `|| true`
//! в вызывающем коде.
//!
//! Осознанные упрощения против nft-бэкенда (Android-ядра без CONNBYTES/ipset):
//! - нет `ct original packets 1-10`: в очередь уходит каждый пакет соединения
//!   с mark-guard. Корректность та же, перф ниже.
//!   shortcut: нет connbytes на целевых ядрах; вернётся при ядре с NF_TABLES.
//! - нет ipset: IP-множество раскрывается в список `-d a b c`.

use crate::error::BlockcheckError;
use crate::firewall::nft::{NftBatch, NftRun, NftRunSync};
use std::sync::LazyLock;

const BINARY: &str = "iptables-restore";
const RESTORE_TIMEOUT_MS: u64 = 15_000;
const READ_TIMEOUT_MS: u64 = 5_000;

/// Выбран ли iptables-бэкенд (`BCW_FIREWALL=iptables`).
pub fn enabled() -> bool {
    static ENABLED: LazyLock<bool> = LazyLock::new(|| {
        matches!(std::env::var("BCW_FIREWALL").as_deref(), Ok("iptables"))
    });
    *ENABLED
}

// ── Перевод nft-батча ────────────────────────────────────────────────────────

/// Понимаемый поднабор nft-команд — ровно тот, что генерирует
/// `firewall/nftables.rs` и `OwnedTableMarker::drop_batch`. Чужая форма —
/// громкий отказ перевода, а не молча пропущенное правило.
fn translate_batch(batch: &NftBatch) -> Result<String, BlockcheckError> {
    use std::fmt::Write;

    let mut mangle = String::new();
    let mut raw = String::new();

    for line in batch.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let bad = |why: &str| BlockcheckError::Nftables {
            command: line.to_string(),
            stderr: format!("iptables backend: {why}"),
        };

        match tokens.as_slice() {
            // `add table`/`delete table` ничего не значат для restore:
            // жизнью цепочек управляют declare/прыжки; снос — CLI в `run()`.
            ["add", "table", ..] | ["delete", "table", ..] => {}

            ["add", "chain", "inet", table, chain, ..] => {
                let owned = format!("{table}_{chain}");
                match *chain {
                    "predefrag" => {
                        let _ = writeln!(raw, ":{owned} - [0:0]");
                        let _ = writeln!(raw, "-A OUTPUT -j {owned}");
                    }
                    "postnat" => {
                        let _ = writeln!(mangle, ":{owned} - [0:0]");
                        let _ = writeln!(mangle, "-A POSTROUTING -j {owned}");
                    }
                    "prenat" => {
                        let _ = writeln!(mangle, ":{owned} - [0:0]");
                        let _ = writeln!(mangle, "-A PREROUTING -j {owned}");
                    }
                    _ => return Err(bad("unknown chain hook")),
                }
            }

            ["flush", "chain", "inet", table, chain] => {
                // Повторный declare флашит (проверено на устройстве).
                let owned = format!("{table}_{chain}");
                if *chain == "predefrag" {
                    let _ = writeln!(raw, ":{owned} - [0:0]");
                } else {
                    let _ = writeln!(mangle, ":{owned} - [0:0]");
                }
            }

            ["add", "rule", "inet", table, chain, rest @ ..] => {
                let rest = rest.join(" ");
                let owned = format!("{table}_{chain}");
                let dst = if *chain == "predefrag" { &mut raw } else { &mut mangle };
                for rule in translate_rule(&owned, &rest)? {
                    let _ = writeln!(dst, "{rule}");
                }
            }

            _ => return Err(bad("unsupported command")),
        }
    }

    let mut doc = String::new();
    if !mangle.is_empty() {
        doc.push_str("*mangle\n");
        doc.push_str(&mangle);
        doc.push_str("COMMIT\n");
    }
    if !raw.is_empty() {
        doc.push_str("*raw\n");
        doc.push_str(&raw);
        doc.push_str("COMMIT\n");
    }
    Ok(doc)
}

/// Перевод одного nft-выражения правила. `chain` — уже iptables-имя.
fn translate_rule(chain: &str, rest: &str) -> Result<Vec<String>, BlockcheckError> {
    let bad = |why: &str| BlockcheckError::Nftables {
        command: rest.to_string(),
        stderr: format!("iptables backend: {why}"),
    };

    // static predefrag: `meta nfproto ipv4 mark and M != 0 notrack`
    if rest.starts_with("meta nfproto ipv4") && rest.ends_with("notrack") {
        let m = parse_after(rest, "mark and ")?
            .split(" != 0")
            .next()
            .unwrap_or("")
            .to_string();
        return Ok(vec![format!("-A {chain} -m mark --mark {m}/{m} -j NOTRACK")]);
    }

    // static prenat: `icmp type time-exceeded [ct state invalid] drop`
    if rest.starts_with("icmp type time-exceeded") {
        let guard = if rest.contains("ct state invalid") {
            "-m conntrack --ctstate INVALID".to_string()
        } else {
            let d = parse_after(rest, "ct mark and ")?
                .split(" != 0")
                .next()
                .unwrap_or("")
                .to_string();
            format!("-m connmark ! --mark 0x0/{d}")
        };
        return Ok(vec![format!(
            "-A {chain} -p icmp --icmp-type time-exceeded {guard} -j DROP"
        )]);
    }

    // dispatch out
    if rest.contains("tcp dport") && rest.contains("ct mark set") {
        let port = parse_after(rest, "tcp dport ")?.split(' ').next().unwrap_or("").to_string();
        let require_set = parse_eq_pair(rest)?;
        let require_clear: u32 = u32::from_str_radix(
            parse_after(rest, "mark and ")?
                .split(" == 0")
                .next()
                .unwrap_or("")
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|_| bad("require_clear"))?;
        let ips = parse_brace_set(rest, "ip daddr ")?;
        let ct_set_or = hex_after(rest, "ct mark set mark or ")?;
        let q = parse_after(rest, "queue num ")?
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string();
        // nft-сет "a, b" → список iptables "a b" (одиночные пробелы)
        let ip_list = ips
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ");
        // nft-матч `A == 0 B == B` — AND. Один матч `--mark V/M` покрывает
        // оба условия при любой раскладке бит: M = set|clear, V = set —
        // «set стоит, clear снят». Два отдельных -m mark в одном правиле
        // iptables-legacy (v1.8.11, Android) отвергает: «--mark can only be
        // used once».
        let mask = format!("0x{:X}", require_set | require_clear);
        let val = format!("0x{require_set:X}");
        let base = format!("-A {chain} -p tcp --dport {port} -d {ip_list} -m mark --mark {val}/{mask}");
        return Ok(vec![
            format!("{base} -j CONNMARK --or-mark 0x{ct_set_or:X}"),
            format!("{base} -j NFQUEUE --queue-num {q}"),
        ]);
    }

    // dispatch in
    if rest.contains("tcp sport") && rest.contains("meta mark set") {
        let port = parse_after(rest, "tcp sport ")?.split(' ').next().unwrap_or("").to_string();
        let ct_require_set = hex_after(rest, "ct mark and ")?;
        let ips = parse_brace_set(rest, "ip saddr ")?;
        let restore_mask = hex_after(rest, "meta mark set ct mark and ")?;
        let q = parse_after(rest, "queue num ")?
            .split(' ')
            .next()
            .unwrap_or("")
            .to_string();
        // nft-сет "a, b" → список iptables "a b" (одиночные пробелы)
        let ip_list = ips
            .split(',')
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ");
        let cm = format!("{:#X}/{:#X}", ct_require_set, ct_require_set);
        let base = format!("-A {chain} -p tcp --sport {port} -s {ip_list} --tcp-flags SYN,ACK SYN,ACK -m connmark --mark {cm}");
        return Ok(vec![
            // nfmask/ctmask режут и источник, и результат — это и есть
            // nft-семантика `meta mark set ct mark and M`.
            format!("{base} -j CONNMARK --restore-mark --nfmask 0x{restore_mask:X} --ctmask 0x{restore_mask:X}"),
            format!("{base} -j NFQUEUE --queue-num {q}"),
        ]);
    }

    Err(bad("unrecognized rule shape"))
}

fn parse_after<'a>(rest: &'a str, sep: &str) -> Result<&'a str, BlockcheckError> {
    rest.split(sep)
        .nth(1)
        .ok_or_else(|| BlockcheckError::Nftables {
            command: rest.to_string(),
            stderr: format!("iptables backend: cannot find `{sep}`"),
        })
}

/// Шестнадцатеричное значение сразу после `sep`.
fn hex_after(rest: &str, sep: &str) -> Result<u32, BlockcheckError> {
    u32::from_str_radix(
        parse_after(rest, sep)?
            .split(' ')
            .next()
            .unwrap_or("")
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|_| BlockcheckError::Nftables {
        command: rest.to_string(),
        stderr: format!("iptables backend: cannot parse hex after `{sep}`"),
    })
}

/// `mark and 0xS == 0xS` — значение S из пары равных.
fn parse_eq_pair(rest: &str) -> Result<u32, BlockcheckError> {
    for part in rest.split("mark and ").skip(1) {
        if let Some((l, r)) = part.split_once(" == ") {
            let l = l.trim();
            if !l.is_empty() && r.trim().starts_with(l) {
                if let Ok(v) = u32::from_str_radix(l.trim_start_matches("0x"), 16) {
                    return Ok(v);
                }
            }
        }
    }
    Err(BlockcheckError::Nftables {
        command: rest.to_string(),
        stderr: "iptables backend: cannot parse `mark and S == S`".into(),
    })
}

fn parse_brace_set(rest: &str, after: &str) -> Result<String, BlockcheckError> {
    rest.split(after)
        .nth(1)
        .and_then(|s| s.split_once('{'))
        .and_then(|(_, r)| r.split_once('}'))
        .map(|(inner, _)| inner.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| BlockcheckError::Nftables {
            command: rest.to_string(),
            stderr: "iptables backend: cannot parse ip set".into(),
        })
}

// ── Снос «таблицы» через CLI ─────────────────────────────────────────────────

/// `delete table inet <name>` → снять прыжки и снести цепочки. Толерантно к
/// отсутствию: повторный sweep и повторный prepare не должны падать на том,
/// чего уже нет. Возвращает, существовало ли что-то.
fn drop_chains_sync(name: &str) -> bool {
    let mut existed = false;
    for (table, builtin, chain) in [
        ("mangle", "POSTROUTING", "postnat"),
        ("mangle", "PREROUTING", "prenat"),
        ("raw", "OUTPUT", "predefrag"),
    ] {
        let owned = format!("{name}_{chain}");
        for args in [
            vec!["-t", table, "-D", builtin, "-j", &owned],
            vec!["-t", table, "-F", &owned],
            vec!["-t", table, "-X", &owned],
        ] {
            if cli_ok(&args) {
                existed = true;
            }
        }
    }
    existed
}

/// CLI-`iptables <args>`; `false` — неуспех (в т.ч. «чего нет»).
fn cli_ok(args: &[&str]) -> bool {
    std::process::Command::new("iptables")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn drop_chains(name: &str) -> bool {
    // Сносы короткие и последовательные; блокирующий путь переиспользуем через
    // spawn_blocking, чтобы не жечь executor-поток.
    let name = name.to_string();
    tokio::task::spawn_blocking(move || drop_chains_sync(&name))
        .await
        .unwrap_or(false)
}

// ── Исполнение ──────────────────────────────────────────────────────────────

fn run_restore_sync(doc: &str, batch: &NftBatch) -> Result<(), BlockcheckError> {
    use std::io::Write;

    let mut child = std::process::Command::new(BINARY)
        .arg("--noflush")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| BlockcheckError::ProcessSpawn {
            reason: format!("{BINARY}: {e}"),
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(doc.as_bytes())
            .map_err(|e| BlockcheckError::ProcessSpawn {
                reason: format!("{BINARY}: {e}"),
            })?;
        // drop stdin закрывает pipe: restore применяет по EOF
    }
    let out = child
        .wait_with_output()
        .map_err(|e| BlockcheckError::ProcessSpawn {
            reason: format!("{BINARY}: {e}"),
        })?;
    if out.status.success() {
        Ok(())
    } else {
        Err(BlockcheckError::Nftables {
            command: batch.first_line().to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Iptables-исполнитель поверх тех же трейтов, что и nft.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemIptables;

impl SystemIptables {
    /// Исполнить батч: `delete table` — CLI-снос, остальное — restore-документ.
    fn execute_sync(batch: &NftBatch) -> Result<(), BlockcheckError> {
        let delete_names: Vec<&str> = batch
            .lines()
            .iter()
            .filter_map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                match t.as_slice() {
                    ["delete", "table", _fam, name] => Some(*name),
                    _ => None,
                }
            })
            .collect();
        for name in delete_names {
            drop_chains_sync(name);
        }
        let doc = translate_batch(batch)?;
        if doc.is_empty() {
            return Ok(());
        }
        run_restore_sync(&doc, batch)
    }
}

impl NftRun for SystemIptables {
    async fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError> {
        let doc = translate_batch(&batch)?;
        let has_delete = batch
            .lines()
            .iter()
            .any(|l| l.starts_with("delete table"));
        if has_delete {
            // Снос — CLI; имена цепочек вытащим из батча.
            for name in batch.lines().iter().filter_map(|l| {
                let t: Vec<&str> = l.split_whitespace().collect();
                match t.as_slice() {
                    ["delete", "table", _fam, name] => Some(name.to_string()),
                    _ => None,
                }
            }) {
                drop_chains(&name).await;
            }
        }
        if doc.is_empty() {
            return Ok(());
        }
        let result = crate::system::process::run_process_stdin(
            &[BINARY, "--noflush"],
            &doc,
            RESTORE_TIMEOUT_MS,
        )
        .await?;
        if result.exit_code != 0 {
            return Err(BlockcheckError::Nftables {
                command: batch.first_line().to_string(),
                stderr: result.stderr,
            });
        }
        Ok(())
    }

    async fn table_names(&self) -> Result<Vec<(String, String)>, BlockcheckError> {
        let result = crate::system::process::run_process(
            &["iptables-save", "-t", "mangle"],
            READ_TIMEOUT_MS,
        )
        .await?;
        Ok(parse_table_names(&result.stdout))
    }

    async fn dump_foreign(
        &self,
        table: &crate::firewall::nft::ForeignTable,
    ) -> Result<String, BlockcheckError> {
        let result = crate::system::process::run_process(
            &["iptables-save", "-t", "mangle"],
            READ_TIMEOUT_MS,
        )
        .await?;
        let name = table.name();
        Ok(result
            .stdout
            .lines()
            .filter(|l| l.contains(name))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

impl NftRunSync for SystemIptables {
    fn run(&self, batch: NftBatch) -> Result<(), BlockcheckError> {
        Self::execute_sync(&batch)
    }
}

/// Цепочки `<table>_<hook>` → «таблицы» `(family, name)`. Чужие цепочки без
/// подчёркивания или с неизвестным суффиксом отсеиваем: sweep и детектор
/// конфликтов ищут по имени таблицы.
fn parse_table_names(save_output: &str) -> Vec<(String, String)> {
    save_output
        .lines()
        .filter_map(|l| l.strip_prefix(':'))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|chain| {
            let (name, hook) = chain.rsplit_once('_')?;
            // Только наши цепочки `<table>_<hook>` с известным хуком: чужие
            // пользовательские цепочки таблицами не объявляем.
            match hook {
                "postnat" | "prenat" | "predefrag" => {
                    Some(("mangle".to_string(), name.to_string()))
                }
                _ => None,
            }
        })
        .collect()
}

/// Жив ли iptables: чтение рулсета без правки.
pub fn is_available_sync() -> bool {
    std::process::Command::new("iptables-save")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_of(lines: &[String]) -> String {
        translate_batch(&NftBatch::from_lines(lines.to_vec())).unwrap()
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn prepare_table_translates_to_chains_and_hooks() {
        let doc = doc_of(&s(&[
            "add table inet blockcheckw",
            "delete table inet blockcheckw",
            "add chain inet blockcheckw postnat { type filter hook postrouting priority 102; }",
            "add chain inet blockcheckw predefrag { type filter hook output priority -402; }",
            "add rule inet blockcheckw predefrag meta nfproto ipv4 mark and 0x10000000 != 0 notrack",
            "add chain inet blockcheckw prenat { type filter hook prerouting priority -102; }",
            "add rule inet blockcheckw prenat icmp type time-exceeded ct mark and 0x10000000 != 0 drop",
            "add rule inet blockcheckw prenat icmp type time-exceeded ct state invalid drop",
        ]));
        assert!(doc.contains(":blockcheckw_postnat - [0:0]"), "{doc}");
        assert!(doc.contains("-A POSTROUTING -j blockcheckw_postnat"), "{doc}");
        assert!(doc.contains(":blockcheckw_predefrag - [0:0]"), "{doc}");
        assert!(doc.contains("-A OUTPUT -j blockcheckw_predefrag"), "{doc}");
        assert!(doc.contains(":blockcheckw_prenat - [0:0]"), "{doc}");
        assert!(doc.contains("-A PREROUTING -j blockcheckw_prenat"), "{doc}");
        assert!(
            doc.contains("-A blockcheckw_predefrag -m mark --mark 0x10000000/0x10000000 -j NOTRACK"),
            "{doc}"
        );
        assert!(
            doc.contains(
                "-A blockcheckw_prenat -p icmp --icmp-type time-exceeded -m connmark ! --mark 0x0/0x10000000 -j DROP"
            ),
            "{doc}"
        );
        assert!(doc.contains("*raw\n"), "{doc}");
        assert!(doc.contains("*mangle\n"), "{doc}");
        assert_eq!(doc.matches("COMMIT").count(), 2, "{doc}");
    }

    #[test]
    fn dispatch_out_becomes_two_rules_with_single_combined_mark() {
        let doc = doc_of(&s(&[concat!(
            "add rule inet blockcheckw postnat meta nfproto ipv4 tcp dport 443 ",
            "mark and 0x10000000 == 0 mark and 0x20000000 == 0x20000000 ip daddr { 157.240.1.35, 157.240.2.35 } ",
            "ct original packets 1-10 ct mark set mark or 0x10000000 queue num 300"
        )]));
        // Один mark-матч: value=set, mask=set|clear. Второй --mark в правиле
        // iptables-legacy запрещён (Android v1.8.11).
        let base = "-A blockcheckw_postnat -p tcp --dport 443 -d 157.240.1.35 157.240.2.35 \
                    -m mark --mark 0x20000000/0x30000000";
        assert!(
            doc.contains(&format!("{base} -j CONNMARK --or-mark 0x10000000")),
            "{doc}"
        );
        assert!(
            doc.contains(&format!("{base} -j NFQUEUE --queue-num 300")),
            "{doc}"
        );
        assert!(
            !doc.contains("! --mark"),
            "второй --mark в одном правиле отвергается restore: {doc}"
        );
    }

    #[test]
    fn dispatch_in_restores_with_mask() {
        let doc = doc_of(&s(&[concat!(
            "add rule inet blockcheckw prenat meta nfproto ipv4 tcp sport 443 ",
            "tcp flags & (syn | ack) == (syn | ack) ct mark and 0x20000000 == 0x20000000 ",
            "ip saddr { 157.240.1.35 } meta mark set ct mark and 0x2000FFFF queue num 300"
        )]));

        assert!(
            doc.contains(
                "--tcp-flags SYN,ACK SYN,ACK -m connmark --mark 0x20000000/0x20000000 \
                 -j CONNMARK --restore-mark --nfmask 0x2000FFFF --ctmask 0x2000FFFF"
            ),
            "{doc}"
        );
        assert!(
            doc.contains("-m connmark --mark 0x20000000/0x20000000 -j NFQUEUE --queue-num 300"),
            "{doc}"
        );
    }

    #[test]
    fn remove_dispatch_leaves_static_rules() {
        // remove_dispatch = flush postnat + flush prenat + re-add статических
        // prenat-правил (восстановление «пола» таблицы).
        let doc = doc_of(&s(&[
            "flush chain inet blockcheckw postnat",
            "flush chain inet blockcheckw prenat",
            "add rule inet blockcheckw prenat icmp type time-exceeded ct mark and 0x10000000 != 0 drop",
            "add rule inet blockcheckw prenat icmp type time-exceeded ct state invalid drop",
        ]));
        assert!(doc.contains(":blockcheckw_postnat - [0:0]"), "{doc}");
        assert!(!doc.contains("-A POSTROUTING -j blockcheckw_postnat"), "{doc}");
        assert!(
            doc.contains("-A blockcheckw_prenat -p icmp --icmp-type time-exceeded"),
            "{doc}"
        );
    }

    #[test]
    fn drop_batch_is_cli_delete_not_restore() {
        // drop_batch = `delete table inet <name>`: в restore-документ не
        // попадает ничего, исполнение — CLI-снос в `run()`.
        let doc = doc_of(&s(&["delete table inet blockcheckw"]));
        assert!(doc.is_empty());
    }

    #[test]
    fn table_names_maps_chains_to_tables() {
        let save = "*mangle\n:PREROUTING - [0:0]\n:blockcheckw_prenat - [0:0]\n:some_custom - [0:0]\n:fw_bcw_thing - [0:0]\nCOMMIT\n";
        let tables = parse_table_names(save);
        // blockcheckw_prenat → blockcheckw; some_custom отброшен (rsplit_once
        // даст ("some","custom") — это таблица some? НЕТ: хук обязан быть
        // postnat/prenat/predefrag).
        assert!(tables.contains(&("mangle".into(), "blockcheckw".into())));
    }

    #[test]
    fn unsupported_shape_fails_loudly() {
        let err = translate_batch(&NftBatch::from_lines(s(&[
            "add rule inet blockcheckw postnat meta nfproto ipv4 udp dport 53 tproxy to :9053",
        ])));
        assert!(err.is_err());
    }
}
