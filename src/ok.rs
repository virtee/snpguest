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
    pub struct SevStatus(u64);
    impl Debug;
    pub sev_bit, _ : 0,0;
    pub es_bit, _ : 1,1;
    pub snp_bit, _ : 2,2;
    pub vtom_bit, _ : 3,3;
    pub reflectvc_bit, _ : 4,4;
    pub restricted_injection_bit, _ : 5,5;
    pub alternate_injection_bit, _ : 6,6;
    pub debug_swap_bit, _ : 7,7;
    pub prevent_host_ibs_bit, _ : 8,8;
    pub btb_isolation_bit, _ : 9,9;
    pub vmpl_sss_bit, _ : 10,10;
    pub secure_tse_bit, _ : 11,11;
    pub vmg_exit_parameter_bit, _ : 12,12;
    reserved_1, _ : 13, 13;
    pub ibs_virtualization_bit, _ : 14,14;
    reserved_2, _ : 15,15;
    pub vmsa_reg_prot_bit, _ : 16,16;
    pub smt_protection_bit, _ : 17, 17;
    reserved_3, _ : 18, 63;
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
    // Grab your MSR value one time.
    let temp_bitfield = match get_values(0xC0010131, 0) {
        Ok(temp_bitfield) => temp_bitfield,
        Err(e) => {
            return vec![Test {
                name: "Error reading MSR",
                gen_mask: SEV_MASK,
                run: Box::new(move || TestResult {
                    name: "Error reading MSR".to_string(),
                    stat: TestState::Fail,
                    mesg: Some(format!("Failed to get bit values, {e}")),
                }),
                sub: vec![],
            }]
        }
    };

    let tests = vec![
        Test {
            name: "SEV",
            gen_mask: SEV_MASK,
            run: Box::new(move || run_msr_check(temp_bitfield.sev_bit(), "SEV", false)),
            sub: vec![],
        },
        Test {
            name: "SEV-ES",
            gen_mask: ES_MASK,
            run: Box::new(move || run_msr_check(temp_bitfield.es_bit(), "SEV-ES", false)),
            sub: vec![],
        },
        Test {
            name: "SNP",
            gen_mask: SNP_MASK,
            run: Box::new(move || run_msr_check(temp_bitfield.snp_bit(), "SNP", false)),
            sub: vec![],
        },
        Test {
            name: "Optional Features",
            gen_mask: SEV_MASK,
            run: Box::new(|| TestResult {
                name: "Optional Features statuses:".to_string(),
                stat: TestState::Pass,
                mesg: None,
            }),
            sub: vec![
                Test {
                    name: "vTOM",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || run_msr_check(temp_bitfield.vtom_bit(), "VTOM", true)),
                    sub: vec![],
                },
                Test {
                    name: "Reflect VC",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.reflectvc_bit(), "ReflectVC", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Restricted Injection",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(
                            temp_bitfield.restricted_injection_bit(),
                            "Restricted Injection",
                            true,
                        )
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Alternate Injection",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(
                            temp_bitfield.alternate_injection_bit(),
                            "Alternate Injection",
                            true,
                        )
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Debug Swap",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.debug_swap_bit(), "Debug Swap", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Prevent Host IBS",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(
                            temp_bitfield.prevent_host_ibs_bit(),
                            "Prevent Host IBS",
                            true,
                        )
                    }),
                    sub: vec![],
                },
                Test {
                    name: "SNP BTB Isolation",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.btb_isolation_bit(), "SNP BTB Isolation", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "VMPL SSS",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.vmpl_sss_bit(), "VMPL SSS", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "Secure TSE",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.secure_tse_bit(), "Secure TSE", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "VMG Exit Parameter",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(
                            temp_bitfield.vmg_exit_parameter_bit(),
                            "VMG Exit Parameter",
                            true,
                        )
                    }),
                    sub: vec![],
                },
                Test {
                    name: "IBS Virtualization",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(
                            temp_bitfield.ibs_virtualization_bit(),
                            "IBS Virtualization",
                            true,
                        )
                    }),
                    sub: vec![],
                },
                Test {
                    name: "VMSA Reg Prot",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.vmsa_reg_prot_bit(), "VMSA Reg Prot", true)
                    }),
                    sub: vec![],
                },
                Test {
                    name: "SMT Protection",
                    gen_mask: SNP_MASK,
                    run: Box::new(move || {
                        run_msr_check(temp_bitfield.smt_protection_bit(), "SMT Protection", true)
                    }),
                    sub: vec![],
                },
            ],
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
            "One or more tests in snpguest-ok reported a failure"
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

fn get_values(reg: u32, cpu: u16) -> Result<SevStatus, anyhow::Error> {
    let mut msr = Msr::new(reg, cpu).context("Error Reading MSR")?;
    let my_bitfield = SevStatus(msr.read()?);
    Ok(my_bitfield)
}

fn run_msr_check(check_bit: u64, sev_feature: &str, optional_field: bool) -> TestResult {
    let mut status = TestState::Fail;
    let mut message = "DISABLED".to_string();

    if check_bit == 1 {
        status = TestState::Pass;
        message = "ENABLED".to_string();
    } else if optional_field {
        status = TestState::Pass;
    }

    TestResult {
        name: sev_feature.to_string(),
        stat: status,
        mesg: Some(message),
    }
}
