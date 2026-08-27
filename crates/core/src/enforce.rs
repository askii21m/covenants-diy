//! Enforcement status of a tapscript under a ruleset.
//!
//! A covenant script that passes because its opcode is inactive is the
//! most dangerous thing this tool could report as success. This classifies
//! a script statically, before execution: does it mean what it reads?

use bitcoin::script::Instruction;
use bitcoin::Script;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Which soft-fork deployments the script is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
#[serde(default)]
pub struct Ruleset {
    pub ctv: bool,
    pub csfs: bool,
    pub cat: bool,
    pub apo: bool,
    /// BIP-446 OP_TEMPLATEHASH (0xce).
    #[serde(default)]
    pub templatehash: bool,
    /// BIP-349 OP_INTERNALKEY (0xcb).
    #[serde(default)]
    pub internalkey: bool,
    /// BIP-442 OP_PAIRCOMMIT (0xcd).
    #[serde(default)]
    pub paircommit: bool,
    /// BIP-346 OP_TXHASH (0xbd).
    #[serde(default)]
    pub txhash: bool,
    /// BIP-443 OP_CHECKCONTRACTVERIFY (0xbb).
    #[serde(default)]
    pub ccv: bool,
    /// BIP-345 OP_VAULT (0xbb) and OP_VAULT_RECOVER (0xbc). Claims the same
    /// opcode as `ccv`, so at most one of the two can be on.
    #[serde(default)]
    pub vault: bool,
}

impl Default for Ruleset {
    fn default() -> Self {
        Ruleset {
            ctv: true,
            csfs: true,
            cat: false,
            apo: false,
            templatehash: false,
            internalkey: false,
            paircommit: false,
            txhash: false,
            ccv: false,
            vault: false,
        }
    }
}

impl Ruleset {
    pub const NONE: Ruleset = Ruleset {
        ctv: false,
        csfs: false,
        cat: false,
        apo: false,
        templatehash: false,
        internalkey: false,
        paircommit: false,
        txhash: false,
        ccv: false,
        vault: false,
    };
    /// Every deployment that can be on at once, resolving the shared opcode
    /// in favour of BIP-443. There is no ruleset with both, so "all" has to
    /// pick one and say which; `ALL_VAULT` is the other side.
    pub const ALL_CCV: Ruleset = Ruleset {
        ctv: true,
        csfs: true,
        cat: true,
        apo: true,
        templatehash: true,
        internalkey: true,
        paircommit: true,
        txhash: true,
        ccv: true,
        vault: false,
    };
    /// `ALL_CCV` with the shared opcode resolved the other way, which is the
    /// only ruleset under which OP_VAULT_RECOVER is enforced.
    pub const ALL_VAULT: Ruleset = Ruleset {
        ccv: false,
        vault: true,
        ..Ruleset::ALL_CCV
    };

    /// BIP-345 and BIP-443 both claim OP_SUCCESS187, so a ruleset with both
    /// on cannot say which opcode 0xbb is. Callers resolve it; this only
    /// reports it.
    pub fn conflict(&self) -> Option<&'static str> {
        if self.vault && self.ccv {
            return Some(
                "OP_VAULT and OP_CHECKCONTRACTVERIFY both use 0xbb, so only one can be enabled",
            );
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Every opcode the script uses is active. It means what it reads.
    Enforced,
    /// An inactive opcode decodes as a NOP, so its condition is silently
    /// absent. The script still executes and may pass.
    Degraded,
    /// A byte the script uses is OP_SUCCESSx under this ruleset. The script
    /// passes unconditionally; anyone can spend.
    Open,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
pub struct EnforcementReport {
    pub status: Enforcement,
    /// Opcodes whose deployment is inactive, by their covenant names.
    pub inactive: Vec<String>,
}

/// BIP-342 OP_SUCCESSx set.
fn is_op_success(op: u8) -> bool {
    matches!(
        op,
        80 | 98 | 126..=129 | 131..=134 | 137 | 138 | 141 | 142 | 149..=153 | 187..=254
    )
}

pub fn classify(script: &Script, rules: &Ruleset) -> EnforcementReport {
    let mut status = Enforcement::Enforced;
    let mut inactive = Vec::new();
    let mut note = |name: &str, worst: Enforcement| {
        if !inactive.iter().any(|n| n == name) {
            inactive.push(name.to_string());
        }
        if worst == Enforcement::Open || status == Enforcement::Enforced {
            status = worst;
        }
    };

    for instruction in script.instructions() {
        let Ok(Instruction::Op(op)) = instruction else {
            continue;
        };
        // Each deployed opcode is matched on its byte alone, never with a
        // guard: a guard that fails falls through to the OP_SUCCESSx arm
        // below, which would report an *active* OP_CAT or
        // OP_CHECKSIGFROMSTACK as "anyone can spend". Both of their bytes
        // are in the OP_SUCCESSx set, so the fallthrough is reachable.
        match op.to_u8() {
            // OP_NOP4: CTV. Inactive, it is a no-op, so the template check
            // vanishes while the push stays on the stack, truthy.
            0xb3 => {
                if !rules.ctv {
                    note("OP_CHECKTEMPLATEVERIFY", Enforcement::Degraded);
                }
            }
            // OP_SUCCESS204: CSFS. Inactive, the whole script passes.
            0xcc => {
                if !rules.csfs {
                    note("OP_CHECKSIGFROMSTACK", Enforcement::Open);
                }
            }
            // OP_SUCCESS126: CAT. Same.
            0x7e => {
                if !rules.cat {
                    note("OP_CAT", Enforcement::Open);
                }
            }
            // OP_SUCCESS203: BIP-349 OP_INTERNALKEY.
            0xcb => {
                if !rules.internalkey {
                    note("OP_INTERNALKEY", Enforcement::Open);
                }
            }
            // OP_SUCCESS187: BIP-443 OP_CHECKCONTRACTVERIFY, or BIP-345
            // OP_VAULT. The byte does not say which, so it is enforced when
            // either is on, and both dormant meanings are named when neither
            // is. Naming one would contradict the disassembly, which reads
            // the byte as whichever deployment the reader has selected.
            0xbb => {
                if !rules.ccv && !rules.vault {
                    note("OP_CHECKCONTRACTVERIFY", Enforcement::Open);
                    note("OP_VAULT", Enforcement::Open);
                }
            }
            // OP_SUCCESS188: BIP-345 OP_VAULT_RECOVER.
            0xbc => {
                if !rules.vault {
                    note("OP_VAULT_RECOVER", Enforcement::Open);
                }
            }
            // OP_SUCCESS189: BIP-346 OP_TXHASH.
            0xbd => {
                if !rules.txhash {
                    note("OP_TXHASH", Enforcement::Open);
                }
            }
            // OP_SUCCESS205: BIP-442 OP_PAIRCOMMIT.
            0xcd => {
                if !rules.paircommit {
                    note("OP_PAIRCOMMIT", Enforcement::Open);
                }
            }
            // OP_SUCCESS206: BIP-446 OP_TEMPLATEHASH.
            0xce => {
                if !rules.templatehash {
                    note("OP_TEMPLATEHASH", Enforcement::Open);
                }
            }
            b if is_op_success(b) => note(&format!("OP_SUCCESS{b}"), Enforcement::Open),
            _ => {}
        }
    }

    // APO is a key type, not an opcode: a BIP-118 key is the single byte
    // 0x01 (pushed as OP_1) or 33 bytes starting 0x01, immediately before a
    // CHECKSIG, CHECKSIGVERIFY or CHECKSIGADD. With APO inactive that is an
    // unknown key type, so any non-empty signature verifies: the signature
    // check is gone, which is Open in effect.
    if !rules.apo {
        let mut prev_is_apo_key = false;
        for instruction in script.instructions() {
            match instruction {
                Ok(Instruction::PushBytes(b)) => {
                    let b = b.as_bytes();
                    prev_is_apo_key = b.len() == 33 && b[0] == 0x01;
                }
                Ok(Instruction::Op(op)) => {
                    let op = op.to_u8();
                    if prev_is_apo_key && matches!(op, 0xac | 0xad | 0xba) {
                        note("ANYPREVOUT", Enforcement::Open);
                    }
                    prev_is_apo_key = op == 0x51;
                }
                Err(_) => break,
            }
        }
    }

    EnforcementReport { status, inactive }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    fn s(hex: &str) -> ScriptBuf {
        use bitcoin::hex::FromHex;
        ScriptBuf::from(Vec::<u8>::from_hex(hex).unwrap())
    }

    #[test]
    fn ctv_enforced_when_active() {
        let r = classify(&s(&format!("20{}b3", "11".repeat(32))), &Ruleset::default());
        assert_eq!(r.status, Enforcement::Enforced);
        assert!(r.inactive.is_empty());
    }

    #[test]
    fn ctv_degrades_when_inactive() {
        let r = classify(&s(&format!("20{}b3", "11".repeat(32))), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Degraded);
        assert_eq!(r.inactive, vec!["OP_CHECKTEMPLATEVERIFY"]);
    }

    #[test]
    fn csfs_is_open_when_inactive() {
        let r = classify(&s("cc"), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Open);
    }

    #[test]
    fn open_beats_degraded() {
        let r = classify(&s(&format!("20{}b3cc", "11".repeat(32))), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Open);
        assert_eq!(r.inactive.len(), 2);
    }

    /// The bug this guards: OP_CAT and OP_CHECKSIGFROMSTACK have bytes
    /// inside the OP_SUCCESSx set, so matching them with a guard let an
    /// *active* deployment fall through and be reported as anyone-can-spend.
    #[test]
    fn an_active_deployment_is_never_reported_as_op_success() {
        let cat = Ruleset {
            cat: true,
            ..Ruleset::NONE
        };
        let r = classify(&s("7e"), &cat);
        assert_eq!(r.status, Enforcement::Enforced);
        assert!(
            r.inactive.is_empty(),
            "active OP_CAT reported as {:?}",
            r.inactive
        );

        let csfs = Ruleset {
            csfs: true,
            ..Ruleset::NONE
        };
        let r = classify(&s("cc"), &csfs);
        assert_eq!(r.status, Enforcement::Enforced);
        assert!(
            r.inactive.is_empty(),
            "active CSFS reported as {:?}",
            r.inactive
        );

        let paircommit = Ruleset {
            paircommit: true,
            ..Ruleset::NONE
        };
        let r = classify(&s("cd"), &paircommit);
        assert_eq!(r.status, Enforcement::Enforced);
        assert!(
            r.inactive.is_empty(),
            "active OP_PAIRCOMMIT reported as {:?}",
            r.inactive
        );

        // The whole merkle-proof leaf, under CAT: enforced, nothing inactive.
        let leaf = classify(
            &s(&format!("a87c7ea8 20{} 87", "33".repeat(32)).replace(' ', "")),
            &cat,
        );
        assert_eq!(leaf.status, Enforcement::Enforced);
        assert!(leaf.inactive.is_empty());
    }

    #[test]
    fn cat_is_open_when_inactive() {
        let r = classify(&s("7e"), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Open);
        assert_eq!(r.inactive, vec!["OP_CAT"]);
    }

    #[test]
    fn paircommit_is_open_when_inactive() {
        let r = classify(&s("cd"), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Open);
        assert_eq!(r.inactive, vec!["OP_PAIRCOMMIT"]);
    }

    /// A byte that is OP_SUCCESSx and belongs to no deployment we model.
    /// The two sides of the shared opcode, so neither reads as anyone-can-
    /// spend under the ruleset that deploys it. 0xbc collides with nothing,
    /// but one flag gates both bytes.
    #[test]
    fn each_side_of_the_shared_opcode_is_enforced_under_its_own_ruleset() {
        assert_eq!(
            classify(&s("bb"), &Ruleset::ALL_CCV).status,
            Enforcement::Enforced
        );
        assert_eq!(
            classify(&s("bb"), &Ruleset::ALL_VAULT).status,
            Enforcement::Enforced
        );
        assert_eq!(
            classify(&s("bc"), &Ruleset::ALL_VAULT).status,
            Enforcement::Enforced
        );
        assert!(Ruleset::ALL_CCV.conflict().is_none());
        assert!(Ruleset::ALL_VAULT.conflict().is_none());
        assert!(Ruleset {
            vault: true,
            ..Ruleset::ALL_CCV
        }
        .conflict()
        .is_some());
    }

    #[test]
    fn an_unmodelled_op_success_is_still_open() {
        let r = classify(&s("62"), &Ruleset::ALL_CCV);
        assert_eq!(r.status, Enforcement::Open);
        assert_eq!(r.inactive, vec!["OP_SUCCESS98"]);
    }

    #[test]
    fn apo_key_is_open_when_inactive() {
        let r = classify(
            &s(&format!("21 01{} ac", "22".repeat(32)).replace(' ', "")),
            &Ruleset::NONE,
        );
        assert_eq!(r.status, Enforcement::Open);
        assert_eq!(r.inactive, vec!["ANYPREVOUT"]);
        let r = classify(&s("51ac"), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Open);
    }

    #[test]
    fn plain_checksig_is_enforced_everywhere() {
        let r = classify(&s(&format!("20{}ac", "22".repeat(32))), &Ruleset::NONE);
        assert_eq!(r.status, Enforcement::Enforced);
    }
}
