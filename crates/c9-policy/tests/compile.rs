// SPDX-License-Identifier: Apache-2.0
use c9_classify::{classify, packet::FrameSpec, Reason};
use c9_policy::*;

const EXAMPLE: &str = include_str!("../../../policy/cortex9.toml");

fn codes(r: Result<Compiled, Vec<Diagnostic>>) -> Vec<&'static str> {
    match r {
        Ok(c) => c.warnings.iter().map(|d| d.code).collect(),
        Err(e) => e.iter().map(|d| d.code).collect(),
    }
}

#[test]
fn example_policy_compiles_cleanly() {
    let c = compile(EXAMPLE).expect("example compiles");
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert_eq!(c.plan.network.deny.len(), 2);
    assert_eq!(c.plan.exec.signatures.len(), 4);
    let w = c.plan.workload("model-shard-loader").unwrap();
    assert_eq!(w.memory_max, Some(256 << 20));
    assert_eq!(w.psi.unwrap().trigger_line(), "some 100000 1000000");
}

#[test]
fn fingerprint_is_canonical() {
    let a = compile(EXAMPLE).unwrap().plan;
    // Same meaning: reordered, duplicated, host bits set, extra comments.
    let reordered = EXAMPLE
        .replace(
            r#"deny_src = ["203.0.113.0/24", "198.51.100.7/32"]"#,
            "# reordered\ndeny_src = [\"198.51.100.7\", \"203.0.113.99/24\", \"203.0.113.0/24\"]",
        )
        .replace(
            r#"deny_dst_ports = ["tcp/23", "tcp/2375", "udp/11211", "udp/1900"]"#,
            r#"deny_dst_ports = ["udp/1900", "tcp/23", "udp/11211", "tcp/2375", "tcp/23"]"#,
        );
    let b = compile(&reordered).unwrap().plan;
    assert_eq!(a.fingerprint_hex(), b.fingerprint_hex());
    let changed = EXAMPLE.replace("generation = 1", "generation = 2");
    assert_ne!(
        a.fingerprint_hex(),
        compile(&changed).unwrap().plan.fingerprint_hex()
    );
}

#[test]
fn cross_pillar_contradiction_is_rejected() {
    let bad = EXAMPLE.replace(r#"expose = ["tcp/8080"]"#, r#"expose = ["tcp/2375"]"#);
    assert_eq!(codes(compile(&bad)), vec!["C9E002"]);
}

#[test]
fn dead_and_redundant_rules_are_reported() {
    let p = EXAMPLE.replace(
        r#"deny_src = ["203.0.113.0/24", "198.51.100.7/32"]"#,
        r#"deny_src = ["203.0.113.0/24", "203.0.113.64/26", "192.0.2.5/32"]"#,
    );
    let mut c = codes(compile(&p));
    c.sort();
    assert_eq!(c, vec!["C9W101", "C9W102"]);
}

#[test]
fn every_error_is_reported_at_once() {
    let p = EXAMPLE
        .replace(r#"memory_high = "224M""#, r#"memory_high = "1G""#)
        .replace("window_ms = 1000", "window_ms = 100")
        .replace(
            r#"watch = ["/opt/cortex9/bin"]"#,
            r#"watch = ["relative/bin"]"#,
        )
        .replace(r#"text = "XMRig/""#, r#"text = "MZ""#)
        .replace(r#""tcp/23""#, r#""tcp/99999""#);
    let mut c = codes(compile(&p));
    c.sort();
    assert_eq!(c, vec!["C9E001", "C9E003", "C9E004", "C9E006", "C9E009"]);
}

#[test]
fn unknown_fields_are_rejected() {
    let p = EXAMPLE.replace(
        "drop_fragments = false",
        "drop_fragments = false\ndrop_everything = true",
    );
    assert_eq!(codes(compile(&p)), vec!["C9E000"]);
}

#[test]
fn plan_drives_the_shared_classifier() {
    let plan = compile(EXAMPLE).unwrap().plan;
    let n = &plan.network;
    let f = |src: [u8; 4], proto: u8, dport: u16| {
        classify(
            &FrameSpec {
                src: u32::from_be_bytes(src),
                proto,
                dport,
                ..Default::default()
            }
            .build(),
            n,
        )
    };
    assert_eq!(f([203, 0, 113, 9], 17, 53), Reason::DropDenySrc);
    assert_eq!(f([10, 1, 1, 1], 6, 2375), Reason::DropDenyPort);
    assert_eq!(f([10, 1, 1, 1], 6, 8080), Reason::PassDefault);
    assert_eq!(f([192, 0, 2, 3], 6, 23), Reason::PassAllowSrc);
}

#[test]
fn map_capacities_match_the_bpf_source() {
    let c = include_str!("../../../bpf/xdp_fw.bpf.c");
    assert!(c.contains(&format!("#define C9_MAX_PREFIXES {XDP_MAX_PREFIXES}")));
    assert!(c.contains(&format!("#define C9_MAX_PORTS {XDP_MAX_PORTS}")));
}

#[test]
fn sizes_parse() {
    assert_eq!(parse_size("max").unwrap(), None);
    assert_eq!(parse_size("64K").unwrap(), Some(65536));
    assert_eq!(parse_size("3G").unwrap(), Some(3 << 30));
    assert!(parse_size("99999999999G").is_err());
    assert!(parse_size("12X").is_err());
}
