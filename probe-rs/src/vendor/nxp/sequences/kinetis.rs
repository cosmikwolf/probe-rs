//! Sequences for NXP Kinetis K-series MCUs.
//!
//! Kinetis K-series chips have a vendor-specific MDM-AP (Mass Debug Module) at
//! AP index 1, separate from the standard AHB-AP at AP 0. The MDM-AP provides:
//!
//! - **Security state** (Status[SYSSEC]): reflects FTFL FSEC[SEC]. When secured,
//!   only MDM Control[FMEIP] is writable — SYS_RES_REQ, CORE_HOLD_RES, and
//!   DBG_REQ are all ignored (ref manual Table 9-5, "Secure" column = N).
//! - **Mass erase** (Control[FMEIP]): erases all flash, sets an internal "mass
//!   erase done" flag that temporarily overrides FSEC security until POR.
//! - **Reset control** (Control[SYS_RES_REQ]): asserts system reset. Status[SYSRES]
//!   reads 0 while in reset, 1 when not in reset (inverted polarity).
//! - **Core hold** (Control[CORE_HOLD_RES]): suspends the core while the system
//!   exits reset, allowing SWD access to flash and RAM before any code executes.
//!   Does NOT set DHCSR.S_HALT (that requires C_DEBUGEN + VC_CORERESET).
//!
//! The WDOG starts with a ~1.25s timeout from every system reset. The unlock
//! sequence (two writes to WDOG_UNLOCK within 20 bus cycles) is too fast for
//! SWD, so we upload a 32-byte Thumb routine to SRAM and execute it at CPU speed.
//!
//! Reference: K20 Sub-Family Reference Manual (K20P64M72SF1RM), OpenOCD kinetis.c,
//! AN4835 "Production Flash Programming Best Practices for Kinetis K- and L-series".

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::MemoryMappedRegister;
use crate::architecture::arm::{
    ArmDebugInterface, ArmError, DapAccess, FullyQualifiedApAddress,
    memory::ArmMemoryInterface,
    sequences::{ArmDebugSequence, ArmDebugSequenceError, DebugEraseSequence},
};
use crate::session::MissingPermissions;

const MDM_AP: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(1);

const MDM_STATUS: u64 = 0x00;
const MDM_CONTROL: u64 = 0x04;
const MDM_IDR: u64 = 0xFC;

const MDM_STAT_FMEACK: u32 = 1 << 0;
const MDM_STAT_FREADY: u32 = 1 << 1;
const MDM_STAT_SYSSEC: u32 = 1 << 2;
const MDM_STAT_SYSRES: u32 = 1 << 3; // 0 = in reset, 1 = not in reset
const MDM_STAT_FMEEN: u32 = 1 << 5;
const MDM_STAT_CORE_HALTED: u32 = 1 << 16;

const MDM_CTRL_FMEIP: u32 = 1 << 0;
const MDM_CTRL_SYS_RES_REQ: u32 = 1 << 3;
const MDM_CTRL_CORE_HOLD_RES: u32 = 1 << 4;

const K_SERIES_MDM_ID: u32 = 0x001C_0000;

/// Debug sequences for Kinetis K-series MCUs.
#[derive(Debug)]
pub struct Kinetis;

impl Kinetis {
    /// Create a new Kinetis debug sequence.
    pub fn create() -> Arc<dyn ArmDebugSequence> {
        Arc::new(Self)
    }

    /// Set C_DEBUGEN + VC_CORERESET via MEM-AP, then release CORE_HOLD_RES.
    ///
    /// Requires CORE_HOLD_RES active (from `mdm_halt`). The core exits the held
    /// state and immediately halts via VC_CORERESET, giving proper S_HALT=1.
    fn enter_debug_halt(
        &self,
        iface: &mut dyn ArmDebugInterface,
        core_ap: &FullyQualifiedApAddress,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::core::armv7m::{Demcr, Dhcsr};

        tracing::debug!("Kinetis: configuring debug halt via MEM-AP");

        {
            let mut core = iface.memory_interface(core_ap)?;

            let mut dhcsr = Dhcsr(0);
            dhcsr.set_c_debugen(true);
            dhcsr.enable_write();
            core.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;

            let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
            demcr.set_vc_corereset(true);
            core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;
        }

        iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, 0)?;

        let start = Instant::now();
        loop {
            let status = iface.read_raw_ap_register(&MDM_AP, MDM_STATUS)?;
            if (status & MDM_STAT_CORE_HALTED) != 0 {
                tracing::debug!("Kinetis: core in debug halt mode (status: {status:#010x})");
                return Ok(());
            }
            if start.elapsed() > Duration::from_millis(500) {
                tracing::warn!(
                    "Kinetis: CORE_HALTED not set after releasing CORE_HOLD_RES \
                     (status: {status:#010x})"
                );
                return Ok(());
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Check if the device is secured by sampling SYSSEC with FREADY+SYSRES gating.
///
/// SYSSEC is unreliable during reset (ref manual Section 9.7) — only trust reads
/// where FREADY=1 AND SYSRES=1. Call `mdm_halt()` first to stabilize the system.
fn is_secured(iface: &mut dyn DapAccess) -> Result<bool, ArmError> {
    let mdm_ap = &MDM_AP;

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let not_in_reset = (status & MDM_STAT_SYSRES) != 0;
        if fready && not_in_reset {
            break;
        }
        if start.elapsed() > Duration::from_secs(3) {
            tracing::warn!("Kinetis: FREADY+SYSRES not both set after 3s (status: {status:#010x})");
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    let mut secured_count = 0u32;
    let mut valid_count = 0u32;
    for _ in 0..64 {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let not_in_reset = (status & MDM_STAT_SYSRES) != 0;
        if fready && not_in_reset {
            valid_count += 1;
            if (status & MDM_STAT_SYSSEC) != 0 {
                secured_count += 1;
            }
        }
        if valid_count >= 32 {
            break;
        }
    }

    tracing::debug!(
        "Kinetis security score: {secured_count}/{valid_count} valid reads show SYSSEC"
    );

    if valid_count == 0 {
        tracing::warn!("Kinetis: no valid security reads — assuming secured");
        return Ok(true);
    }

    Ok(secured_count > valid_count / 2)
}

/// Hold the core at reset via MDM-AP CORE_HOLD_RES + system reset cycle.
///
/// After this, the core is suspended at the reset vector with flash/RAM accessible
/// via MEM-AP. CORE_HOLD_RES remains asserted — the caller must release it.
/// On secured chips, CORE_HOLD_RES is silently ignored (Secure=N).
fn mdm_halt(iface: &mut dyn DapAccess) -> Result<(), ArmError> {
    let mdm_ap = &MDM_AP;

    tracing::debug!("Kinetis: performing MDM halt (CORE_HOLD_RES + system reset)");

    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;
    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
    )?;

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) == 0 {
            break;
        }
        if start.elapsed() > Duration::from_millis(500) {
            tracing::warn!("Kinetis MDM halt: timeout waiting for SYSRES");
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) != 0 {
            tracing::debug!("Kinetis MDM halt: system out of reset (status: {status:#010x})");
            break;
        }
        if start.elapsed() > Duration::from_millis(500) {
            tracing::warn!("Kinetis MDM halt: timeout waiting for reset exit");
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_CORE_HALTED) != 0 {
            tracing::debug!(
                "Kinetis MDM halt: core halted at reset vector (status: {status:#010x})"
            );
            break;
        }
        if start.elapsed() > Duration::from_millis(500) {
            // Expected: CORE_HALTED requires C_DEBUGEN which isn't set yet.
            // CORE_HOLD_RES still prevents execution. enter_debug_halt
            // will set C_DEBUGEN and VC_CORERESET to achieve proper halt.
            tracing::debug!(
                "Kinetis MDM halt: CORE_HALTED not set (status: {status:#010x}), \
                 CORE_HOLD_RES prevents execution"
            );
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    Ok(())
}

/// Perform mass erase via MDM-AP FMEIP. See AN4835 Section 4.2.1.
///
/// Asserts hardware nRST to hold the system in stable reset, breaking any
/// lockup/WDOG reset loop. While held, the flash controller still initializes
/// (FREADY=1 with SYSRES=0 — ref manual Section 9.5.2). Once FREADY is stable
/// for 32 consecutive reads, FMEIP is written with nRST still held. The erase
/// completes under reset; nRST is released only after FMEIP clears.
///
/// On secured chips, only FMEIP is writable in MDM Control (Table 9-5) —
/// SYS_RES_REQ, CORE_HOLD_RES, and DBG_REQ are all ignored. Hardware nRST is
/// the only way to stabilize a secured chip in a lockup loop.
///
/// Follows the proven OpenOCD `kinetis_mdm_mass_erase` sequence.
fn kinetis_mass_erase(iface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
    use crate::architecture::arm::traits::Pins;

    let mdm_ap = &MDM_AP;
    let n_reset_mask = {
        let mut p = Pins(0);
        p.set_nreset(true);
        p.0 as u32
    };

    // --- Step 1: Assert hardware nRST ---
    tracing::debug!("Kinetis mass erase: asserting nRST");
    match iface.swj_pins(0, n_reset_mask, 0) {
        Ok(pins) => tracing::debug!("Kinetis mass erase: nRST asserted (pins={pins:#010x})"),
        Err(e) => {
            tracing::warn!("Kinetis mass erase: swj_pins not supported ({e}), trying without nRST");
            return kinetis_mass_erase_no_nrst(iface);
        }
    }

    // Let the system settle in reset. The flash controller initializes
    // independently and will report FREADY=1 while the system is held in reset.
    thread::sleep(Duration::from_millis(100));

    // Write SYS_RES_REQ for good measure (matches OpenOCD; ignored on secured chips).
    let _ = iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_SYS_RES_REQ);

    // --- Step 2: Verify MDM-AP is accessible and check FMEEN ---
    let status = match iface.read_raw_ap_register(mdm_ap, MDM_STATUS) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Kinetis mass erase: cannot read MDM Status while nRST held ({e})");
            let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
            return Err(e);
        }
    };
    tracing::debug!("Kinetis mass erase: MDM Status while nRST held = {status:#010x}");

    if (status & MDM_STAT_FMEEN) == 0 {
        let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
        return Err(ArmDebugSequenceError::custom(
            "Kinetis mass erase is disabled (FMEEN=0). Device may be permanently locked.",
        )
        .into());
    }

    // --- Step 3: Wait for FREADY=1 + SYSRES=0 (flash ready while in reset) ---
    // 32 consecutive matching reads required for stability, matching OpenOCD.
    let start = Instant::now();
    let mut ready_count = 0u32;
    let mut last_log = Instant::now();

    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let in_reset = (status & MDM_STAT_SYSRES) == 0;

        if fready && in_reset {
            ready_count += 1;
        } else {
            if ready_count > 0 {
                tracing::debug!(
                    "Kinetis mass erase: FREADY/SYSRES unstable, resetting count \
                     (was {ready_count}, status={status:#010x})"
                );
            }
            ready_count = 0;
        }

        if ready_count >= 32 {
            tracing::debug!("Kinetis mass erase: FREADY stable for 32 reads");
            break;
        }

        if last_log.elapsed() > Duration::from_secs(1) {
            tracing::debug!(
                "Kinetis mass erase: waiting for FREADY — status={status:#010x}, \
                 ready_count={ready_count}, elapsed={}ms",
                start.elapsed().as_millis()
            );
            last_log = Instant::now();
        }

        if start.elapsed() > Duration::from_secs(5) {
            tracing::error!(
                "Kinetis mass erase: FREADY not stable after 5s while nRST held \
                 (status={status:#010x}, ready_count={ready_count})"
            );
            let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
            return Err(ArmDebugSequenceError::custom(
                "Kinetis: flash controller not ready while nRST held. \
                 Check probe nRST connection.",
            )
            .into());
        }
    }

    // --- Step 4: Write FMEIP (with SYS_RES_REQ, matching OpenOCD) ---
    tracing::debug!("Kinetis mass erase: writing SYS_RES_REQ | FMEIP");
    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_FMEIP,
    )?;

    let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
    if (control & MDM_CTRL_FMEIP) == 0 {
        // Try writing just FMEIP (maybe SYS_RES_REQ interferes on secured chips)
        tracing::debug!(
            "Kinetis mass erase: FMEIP not set with SYS_RES_REQ (ctrl={control:#010x}), \
             retrying with FMEIP only"
        );
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_FMEIP)?;
        let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
        if (control & MDM_CTRL_FMEIP) == 0 {
            tracing::error!(
                "Kinetis mass erase: FMEIP not accepted (ctrl={control:#010x})"
            );
            let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
            return Err(ArmDebugSequenceError::custom(
                "Kinetis: FMEIP write rejected while nRST held and FREADY=1. \
                 This should not happen — check hardware.",
            )
            .into());
        }
    }

    tracing::info!("Kinetis mass erase: FMEIP accepted, erase in progress");

    // --- Step 5: Poll FMEIP=0 (erase complete), nRST still held ---
    // 16s timeout per OpenOCD (3.6s per 512kB block, 4 blocks max).
    let start = Instant::now();
    let timeout = Duration::from_secs(16);
    let mut last_log = Instant::now();
    loop {
        let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
        if (control & MDM_CTRL_FMEIP) == 0 {
            tracing::info!(
                "Kinetis mass erase complete (took {}ms)",
                start.elapsed().as_millis()
            );
            break;
        }
        if last_log.elapsed() > Duration::from_secs(2) {
            let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
            let fmeack = if (status & MDM_STAT_FMEACK) != 0 {
                "yes"
            } else {
                "no"
            };
            tracing::info!(
                "Kinetis mass erase: waiting — ctrl={control:#010x}, \
                 status={status:#010x}, FMEACK={fmeack}, elapsed={}ms",
                start.elapsed().as_millis()
            );
            last_log = Instant::now();
        }
        if start.elapsed() > timeout {
            let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
            tracing::error!(
                "Timeout waiting for mass erase — ctrl={control:#010x}, status={status:#010x}"
            );
            let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
            return Err(ArmError::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }

    // --- Step 6: Post-erase — ensure unsecured, hold core, release nRST ---
    // nRST is still held. The "mass erase done" flag should override FSEC security,
    // but the MDM-AP may not reflect the new security state until a reset cycle.
    thread::sleep(Duration::from_millis(100));

    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    let still_secured = (status & MDM_STAT_SYSSEC) != 0;
    tracing::info!(
        "Kinetis: post-erase MDM Status = {status:#010x}, SYSSEC={}",
        if still_secured { "still secured" } else { "unsecured" }
    );

    if still_secured {
        // Security override needs a reset cycle. Briefly release nRST to let the
        // system reset, then re-assert to prevent lockup on blank flash.
        tracing::debug!("Kinetis: cycling nRST for security override to take effect");
        let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0); // release
        thread::sleep(Duration::from_millis(10));
        let _ = iface.swj_pins(0, n_reset_mask, 0); // re-assert
        thread::sleep(Duration::from_millis(100));

        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        tracing::info!(
            "Kinetis: post-nRST-cycle MDM Status = {status:#010x}, SYSSEC={}",
            if (status & MDM_STAT_SYSSEC) != 0 { "still secured!" } else { "unsecured" }
        );
    }

    // Chip should be unsecured now — CORE_HOLD_RES and SYS_RES_REQ should work.
    // Set CORE_HOLD_RES + SYS_RES_REQ to hold the core when reset exits.
    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
    )?;

    // Verify the control bits were accepted (they're ignored if still secured).
    let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
    if (control & MDM_CTRL_CORE_HOLD_RES) == 0 {
        tracing::warn!(
            "Kinetis: CORE_HOLD_RES not accepted (ctrl={control:#010x}). \
             Core may enter lockup on blank flash after reset."
        );
    } else {
        tracing::debug!("Kinetis: CORE_HOLD_RES accepted (ctrl={control:#010x})");
    }

    // Release nRST — SYS_RES_REQ keeps the system in reset.
    tracing::debug!("Kinetis mass erase: releasing nRST");
    let _ = iface.swj_pins(n_reset_mask, n_reset_mask, 0);
    thread::sleep(Duration::from_millis(10));

    // Release SYS_RES_REQ, keeping CORE_HOLD_RES — core is suspended at reset vector.
    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) != 0 {
            tracing::debug!(
                "Kinetis mass erase: system out of reset, core held (status: {status:#010x})"
            );
            break;
        }
        if start.elapsed() > Duration::from_secs(2) {
            tracing::warn!(
                "Kinetis mass erase: timeout waiting for reset exit (status: {status:#010x})"
            );
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

/// Fallback mass erase without hardware nRST (for probes without reset line).
///
/// Uses SYS_RES_REQ to hold the system in reset. This only works on unsecured
/// chips (or chips where SYS_RES_REQ is functional). On secured chips in a
/// lockup loop, this will fail — hardware nRST is required.
fn kinetis_mass_erase_no_nrst(iface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
    let mdm_ap = &MDM_AP;

    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    tracing::debug!("Kinetis mass erase (no nRST): MDM Status = {status:#010x}");

    if (status & MDM_STAT_FMEEN) == 0 {
        return Err(ArmDebugSequenceError::custom(
            "Kinetis mass erase is disabled (FMEEN=0). Device may be permanently locked.",
        )
        .into());
    }

    // Try SYS_RES_REQ to hold system in reset (ignored on secured chips).
    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_SYS_RES_REQ)?;
    thread::sleep(Duration::from_millis(100));

    // Wait for FREADY=1 + SYSRES=0.
    let start = Instant::now();
    let mut ready_count = 0u32;
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let in_reset = (status & MDM_STAT_SYSRES) == 0;

        if fready && in_reset {
            ready_count += 1;
        } else {
            ready_count = 0;
        }

        if ready_count >= 32 {
            break;
        }

        if start.elapsed() > Duration::from_secs(3) {
            return Err(ArmDebugSequenceError::custom(
                "Kinetis: flash not ready for mass erase. If device is secured \
                 and in a reset loop, hardware nRST is required.",
            )
            .into());
        }
    }

    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_FMEIP,
    )?;

    // Poll FMEIP=0.
    let start = Instant::now();
    loop {
        let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
        if (control & MDM_CTRL_FMEIP) == 0 {
            tracing::info!(
                "Kinetis mass erase complete (took {}ms)",
                start.elapsed().as_millis()
            );
            break;
        }
        if start.elapsed() > Duration::from_secs(16) {
            return Err(ArmError::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Post-erase: hold core at reset vector.
    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
    )?;
    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;
    thread::sleep(Duration::from_millis(100));

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) != 0 {
            break;
        }
        if start.elapsed() > Duration::from_secs(2) {
            tracing::warn!("Kinetis mass erase: timeout waiting for system to exit reset");
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    Ok(())
}

/// Disable the WDOG by uploading a 32-byte Thumb routine to SRAM and executing it.
///
/// The WDOG unlock requires two writes within 20 bus cycles — too fast for SWD.
/// Core must be halted. Based on OpenOCD's `armv7m_kinetis_wdog.s`.
fn disable_wdog(core: &mut dyn ArmMemoryInterface) -> Result<(), ArmError> {
    use crate::architecture::arm::core::armv7m::Dhcsr;

    // R0 = WDOG base. Unlock (0xC520, 0xD928) → clear STCTRLH.WDOGEN → bkpt.
    #[rustfmt::skip]
    const WDOG_ALGO: [u32; 8] = [
        0x81c2_4a04, // ldr  r2, [pc,#16]; strh r2, [r0,#0xe]  ; UNLOCK = 0xC520
        0x81c2_4a04, // ldr  r2, [pc,#16]; strh r2, [r0,#0xe]  ; UNLOCK = 0xD928
        0x8802_2401, // movs r4, #1;       ldrh r2, [r0,#0]     ; read STCTRLH
        0x8002_43a2, // bics r2, r4;       strh r2, [r0,#0]     ; clear WDOGEN
        0x0000_e005, // b    +10;          (padding)
        0x0000_c520, // .word 0x0000C520   (WDOG_KEY1)
        0x0000_d928, // .word 0x0000D928   (WDOG_KEY2)
        0xbe00_0000, // (align);           bkpt #0               ; halt
    ];

    const WDOG_BASE: u32 = 0x4005_2000;
    const ALGO_ADDR: u32 = 0x2000_0000; // SRAM_U base
    const DCRDR: u64 = 0xE000_EDF8;
    const DCRSR: u64 = 0xE000_EDF4;

    tracing::debug!("Kinetis: disabling WDOG via uploaded algorithm");
    match core.read_word_32(Dhcsr::get_mmio_address()) {
        Ok(val) if (val & (1 << 17)) != 0 => {} // S_HALT
        Ok(_) => {
            tracing::debug!("Kinetis WDOG: core not halted, skipping disable");
            return Ok(());
        }
        Err(_) => {
            tracing::debug!("Kinetis WDOG: MEM-AP not accessible, skipping disable");
            return Ok(());
        }
    }

    core.write_word_32(DCRSR, 15)?;
    let saved_pc = core.read_word_32(DCRDR)?;

    for (i, &word) in WDOG_ALGO.iter().enumerate() {
        core.write_word_32(ALGO_ADDR as u64 + i as u64 * 4, word)?;
    }

    core.write_word_32(DCRDR, WDOG_BASE)?;
    core.write_word_32(DCRSR, 1 << 16)?; // Write R0
    core.write_word_32(DCRDR, ALGO_ADDR)?;
    core.write_word_32(DCRSR, (1 << 16) | 15)?; // PC

    // Resume — algorithm hits bkpt when done
    let mut dhcsr = Dhcsr(0);
    dhcsr.enable_write();
    dhcsr.set_c_debugen(true);
    core.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;
    let start = Instant::now();
    loop {
        let dhcsr_val = core.read_word_32(Dhcsr::get_mmio_address())?;
        if (dhcsr_val & (1 << 17)) != 0 {
            break;
        }
        if start.elapsed() > Duration::from_millis(500) {
            tracing::warn!("Kinetis WDOG disable: algorithm timeout, force-halting");
            let mut dhcsr = Dhcsr(0);
            dhcsr.enable_write();
            dhcsr.set_c_debugen(true);
            dhcsr.set_c_halt(true);
            core.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    core.write_word_32(DCRDR, saved_pc)?;
    core.write_word_32(DCRSR, (1 << 16) | 15)?; // PC
    let stctrlh = core.read_word_32(WDOG_BASE as u64)?;
    if (stctrlh & 1) == 0 {
        tracing::debug!("Kinetis WDOG disabled successfully (STCTRLH = {stctrlh:#06x})");
    } else {
        tracing::warn!("Kinetis WDOG disable may have failed (STCTRLH = {stctrlh:#06x})");
    }

    Ok(())
}

impl ArmDebugSequence for Kinetis {
    fn debug_device_unlock(
        &self,
        iface: &mut dyn ArmDebugInterface,
        _default_ap: &FullyQualifiedApAddress,
        permissions: &crate::Permissions,
    ) -> Result<(), ArmError> {
        let mdm_ap = &MDM_AP;

        let mdm_idr = iface.read_raw_ap_register(mdm_ap, MDM_IDR)?;
        tracing::debug!("Kinetis MDM-AP IDR: {mdm_idr:#010x}");
        if mdm_idr != K_SERIES_MDM_ID {
            tracing::warn!(
                "Unexpected MDM-AP IDR: {mdm_idr:#010x} (expected {K_SERIES_MDM_ID:#010x})"
            );
        }

        // Stabilize system before checking security — on blank flash chips in a
        // WDOG reset loop, this holds the core so is_secured() gets reliable reads.
        mdm_halt(iface)?;

        if !is_secured(iface)? {
            tracing::info!("Kinetis device is unsecured");

            if let Err(e) = self.enter_debug_halt(iface, _default_ap) {
                tracing::warn!("Kinetis: first debug halt attempt failed ({e}), retrying mdm_halt");
                mdm_halt(iface)?;
                self.enter_debug_halt(iface, _default_ap)?;
            }

            return Ok(());
        }

        tracing::warn!("Kinetis device is SECURED. Mass erase will be performed to unlock.");
        permissions
            .erase_all()
            .map_err(|MissingPermissions(desc)| ArmError::MissingPermissions(desc))?;

        kinetis_mass_erase(iface)?;

        // Re-attach required — SYSSEC is unreliable immediately after erase.
        // On reconnect, the "mass erase done" flag keeps the chip unsecured.
        tracing::info!("Kinetis mass erase done, re-attaching probe");
        Err(ArmError::ReAttachRequired)
    }

    fn reset_catch_set(
        &self,
        core: &mut dyn ArmMemoryInterface,
        _core_type: crate::CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::core::armv7m::{Demcr, Dhcsr};

        // Use VC_CORERESET (not MDM CORE_HOLD_RES) — gives proper S_HALT=1.
        let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
        demcr.set_vc_corereset(true);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;

        let _ = core.read_word_32(Dhcsr::get_mmio_address())?;

        Ok(())
    }

    fn reset_catch_clear(
        &self,
        core: &mut dyn ArmMemoryInterface,
        _core_type: crate::CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::core::armv7m::Demcr;

        // WDOG restarts on every system reset — disable while core is halted.
        if let Err(e) = disable_wdog(core) {
            tracing::debug!("Kinetis: WDOG disable skipped ({e}), firmware must handle WDOG");
        }

        let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
        demcr.set_vc_corereset(false);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;

        Ok(())
    }

    fn reset_system(
        &self,
        interface: &mut dyn ArmMemoryInterface,
        core_type: crate::CoreType,
        debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        let core_ap = interface.fully_qualified_address();

        let iface = interface
            .get_arm_debug_interface()
            .map_err(ArmError::from)?;

        tracing::debug!("Kinetis: asserting system reset via MDM-AP");
        iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, MDM_CTRL_SYS_RES_REQ)?;

        let start = Instant::now();
        loop {
            let status = iface.read_raw_ap_register(&MDM_AP, MDM_STATUS)?;
            if (status & MDM_STAT_SYSRES) == 0 {
                break;
            }
            if start.elapsed() >= Duration::from_millis(500) {
                tracing::warn!("Timeout waiting for SYSRES, continuing anyway");
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, 0)?;

        let start = Instant::now();
        loop {
            let status = iface.read_raw_ap_register(&MDM_AP, MDM_STATUS)?;
            if (status & MDM_STAT_SYSRES) != 0 {
                break;
            }
            if start.elapsed() >= Duration::from_millis(500) {
                tracing::warn!("Timeout waiting for system to exit reset");
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }

        self.debug_core_start(iface, &core_ap, core_type, debug_base, None)?;

        Ok(())
    }

    fn debug_erase_sequence(&self) -> Option<Arc<dyn DebugEraseSequence>> {
        Some(Arc::new(KinetisEraseSequence))
    }

    fn allowed_access_ports(&self) -> Vec<u8> {
        vec![0, 1] // AHB-AP + MDM-AP
    }
}

/// Standalone chip-erase via MDM-AP (e.g. `probe-rs erase`).
#[derive(Debug)]
struct KinetisEraseSequence;

impl DebugEraseSequence for KinetisEraseSequence {
    fn erase_all(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        tracing::info!("Kinetis chip erase via MDM-AP");
        kinetis_mass_erase(interface)?;
        Err(ArmError::ReAttachRequired)
    }
}
