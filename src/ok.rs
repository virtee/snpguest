use super::*;

use std::fmt;

use bitfield::bitfield;
use colorful::*;
use msru::*;
use serde::{Deserialize, Serialize};

const SEV_MASK: usize = 1;
const ES_MASK: usize = 1 << 1;
const SNP_MASK: usize = 1 << 2;
type TestFn = dyn Fn() -> TestResult;

struct Test {
    name: &'static str,
    gen_mask: usize,
    run: Box<TestFn>,
    sub: Vec<Test>,
}

struct TestResult {
    name: String,
    stat: TestState,
    mesg: Option<String>,
}

#[derive(PartialEq, Eq)]
enum TestState {
    Pass,
    Skip,
    Fail,
}

bitfield! {
    #[repr(C)]
    #[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct BitRead(u64);
    impl Debug;
    pub sev_bit, _: 0,0;
    pub es_bit, _: 1,1;
    pub snp_bit, _:2,2;
}

enum GuestLevels {
    Sev,
    SevEs,
    Snp,
}

impl fmt::Display for GuestLevels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            GuestLevels::Sev => "SEV",
            GuestLevels::SevEs => "SEV-ES",
            GuestLevels::Snp => "SNP",
        };
        write!(f, "{}", s)
    }
}

impl fmt::Display for TestState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TestState::Pass => format!("{}", "PASS".green()),
            TestState::Skip => format!("{}", "SKIP".yellow()),
            TestState::Fail => format!("{}", "FAIL".red()),
        };

        write!(f, "{}", s)
    }
}

fn collect_tests() -> Vec<Test> {
    let tests = vec![
        Test {
            name: "SEV",
            gen_mask: SEV_MASK,
            run: Box::new(|| encryption_levels(GuestLevels::Sev)),
            sub: vec![],
        },
        Test {
            name: "SEV-ES",
            gen_mask: ES_MASK,
            run: Box::new(|| encryption_levels(GuestLevels::SevEs)),
            sub: vec![],
        },
        Test {
            name: "SNP",
            gen_mask: SNP_MASK,
            run: Box::new(|| encryption_levels(GuestLevels::Snp)),
            sub: vec![],
        },
    ];
    tests
}

const INDENT: usize = 2;

pub fn cmd(quiet: bool) -> Result<()> {
    let tests = collect_tests();

    if run_test(&tests, 0, quiet, SEV_MASK | ES_MASK | SNP_MASK) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "One or more tests in sevctl-ok reported a failure"
        ))
    }
}

fn run_test(tests: &[Test], level: usize, quiet: bool, mask: usize) -> bool {
    let mut passed = true;

    for t in tests {
        // Skip tests that aren't included in the specified generation.
        if (t.gen_mask & mask) != t.gen_mask {
            test_gen_not_included(t, level, quiet);
            continue;
        }

        let res = (t.run)();
        emit_result(&res, level, quiet);
        match res.stat {
            TestState::Pass => {
                if !run_test(&t.sub, level + INDENT, quiet, mask) {
                    passed = false;
                }
            }
            TestState::Fail => {
                passed = false;
                emit_skip(&t.sub, level + INDENT, quiet);
            }
            // Skipped tests are marked as skip before recursing. They are just emitted and not actually processed.
            TestState::Skip => unreachable!(),
        }
    }

    passed
}

fn emit_result(res: &TestResult, level: usize, quiet: bool) {
    if !quiet {
        let msg = match &res.mesg {
            Some(m) => format!(": {}", m),
            None => "".to_string(),
        };
        println!(
            "[ {:^4} ] {:width$}- {}{}",
            format!("{}", res.stat),
            "",
            res.name,
            msg,
            width = level
        )
    }
}

fn test_gen_not_included(test: &Test, level: usize, quiet: bool) {
    if !quiet {
        let tr_skip = TestResult {
            name: test.name.to_string(),
            stat: TestState::Skip,
            mesg: None,
        };

        println!(
            "[ {:^4} ] {:width$}- {}",
            format!("{}", tr_skip.stat),
            "",
            tr_skip.name,
            width = level
        );
        emit_skip(&test.sub, level + INDENT, quiet);
    }
}

fn emit_skip(tests: &[Test], level: usize, quiet: bool) {
    if !quiet {
        for t in tests {
            let tr_skip = TestResult {
                name: t.name.to_string(),
                stat: TestState::Skip,
                mesg: None,
            };

            println!(
                "[ {:^4} ] {:width$}- {}",
                format!("{}", tr_skip.stat),
                "",
                tr_skip.name,
                width = level
            );
            emit_skip(&t.sub, level + INDENT, quiet);
        }
    }
}

fn get_values(reg: u32, cpu: u16) -> Result<BitRead, anyhow::Error> {
    let mut msr = Msr::new(reg, cpu).context("Error Reading MSR")?;
    let my_bitfield = BitRead(msr.read()?);
    Ok(my_bitfield)
}

fn encryption_levels(test: GuestLevels) -> TestResult {
    let temp_bitfield = match get_values(0xC0010131, 0) {
        Ok(temp_bitfield) => temp_bitfield,
        Err(e) => {
            return TestResult {
                name: test.to_string(),
                stat: TestState::Fail,
                mesg: Some(format!("Failed to get bit values, {e}")),
            }
        }
    };

    match test {
        GuestLevels::Sev => {
            let sev_status = temp_bitfield.sev_bit();
            if sev_status == 1 {
                TestResult {
                    name: format!("{}", GuestLevels::Sev),
                    stat: TestState::Pass,
                    mesg: Some("SEV is ENABLED".to_string()),
                }
            } else if sev_status == 0 {
                TestResult {
                    name: format!("{}", GuestLevels::Sev),
                    stat: TestState::Fail,
                    mesg: Some("SEV is DISABLED".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", GuestLevels::Sev),
                    stat: TestState::Fail,
                    mesg: format!("Invalid value found in MSR, {}", sev_status).into(),
                }
            }
        }
        GuestLevels::SevEs => {
            let sev_es_status = temp_bitfield.es_bit();
            if sev_es_status == 1 {
                TestResult {
                    name: format!("{}", GuestLevels::SevEs),
                    stat: TestState::Pass,
                    mesg: Some("SEV-ES is ENABLED".to_string()),
                }
            } else if sev_es_status == 0 {
                TestResult {
                    name: format!("{}", GuestLevels::SevEs),
                    stat: TestState::Fail,
                    mesg: Some("SEV-ES is DISABLED".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", GuestLevels::SevEs),
                    stat: TestState::Fail,
                    mesg: format!("Invalid value found in MSR, {}", sev_es_status).into(),
                }
            }
        }
        GuestLevels::Snp => {
            let snp_status = temp_bitfield.snp_bit();
            if snp_status == 1 {
                TestResult {
                    name: format!("{}", GuestLevels::Snp),
                    stat: TestState::Pass,
                    mesg: Some("SNP is ENABLED".to_string()),
                }
            } else if snp_status == 0 {
                TestResult {
                    name: format!("{}", GuestLevels::Snp),
                    stat: TestState::Fail,
                    mesg: Some("SNP is DISABLED".to_string()),
                }
            } else {
                TestResult {
                    name: format!("{}", GuestLevels::Snp),
                    stat: TestState::Fail,
                    mesg: format!("Invalid value found in MSR, {}", snp_status).into(),
                }
            }
        }
    }
}
