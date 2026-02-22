//! Debug sequences for NXP Kinetis K-series (MK10, MK20, MK40, MK60, etc.)
//!
//! Kinetis K-series chips use a vendor-specific MDM-AP (Mass Debug Module Access Port)
//! at AP index 1 for chip security, mass erase, and reset control. This module implements
//! the MDM-AP debug sequences so that probe-rs can reliably connect to, flash, and debug
//! these chips.
//!
//! Reference: NXP Kinetis K-series reference manuals, OpenOCD `kinetis.c`,
//! AN4835 "Production Flash Programming Best Practices for Kinetis K- and L-series MCUs".

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::architecture::arm::{
    ArmDebugInterface, ArmError, DapAccess, FullyQualifiedApAddress,
    memory::ArmMemoryInterface,
    sequences::{ArmDebugSequence, ArmDebugSequenceError, DebugEraseSequence},
};
use crate::session::MissingPermissions;
use crate::MemoryMappedRegister;

// MDM-AP is at Access Port index 1 on Kinetis K-series.
const MDM_AP: FullyQualifiedApAddress = FullyQualifiedApAddress::v1_with_default_dp(1);

// MDM-AP register offsets
const MDM_STATUS: u64 = 0x00;
const MDM_CONTROL: u64 = 0x04;
const MDM_IDR: u64 = 0xFC;

// MDM-AP Status register bits
const MDM_STAT_FMEACK: u32 = 1 << 0;
const MDM_STAT_FREADY: u32 = 1 << 1;
const MDM_STAT_SYSSEC: u32 = 1 << 2;
const MDM_STAT_SYSRES: u32 = 1 << 3;
const MDM_STAT_FMEEN: u32 = 1 << 5;
const MDM_STAT_CORE_HALTED: u32 = 1 << 16;

// MDM-AP Control register bits
const MDM_CTRL_FMEIP: u32 = 1 << 0;
const MDM_CTRL_SYS_RES_REQ: u32 = 1 << 3;
const MDM_CTRL_CORE_HOLD_RES: u32 = 1 << 4;

// Expected MDM-AP IDR value for K-series
const K_SERIES_MDM_ID: u32 = 0x001C_0000;

/// Debug sequences for NXP Kinetis K-series MCUs.
///
/// Handles MDM-AP based security unlock (mass erase), reset control via
/// CORE_HOLD_RES, and system reset via SYS_RES_REQ.
#[derive(Debug)]
pub struct Kinetis;

impl Kinetis {
    /// Create a new Kinetis debug sequence.
    pub fn create() -> Arc<dyn ArmDebugSequence> {
        Arc::new(Self)
    }
}

/// Check if the Kinetis device is secured, with proper FREADY gating.
///
/// Only trusts SYSSEC readings when FREADY=1 AND SYSRES=1 (system not in reset).
/// During reset, the security status is being determined (ref manual Section 9.7)
/// and SYSSEC may transiently read as 1 even on unsecured/temporarily-unsecured chips.
fn is_secured(iface: &mut dyn DapAccess) -> Result<bool, ArmError> {
    let mdm_ap = &MDM_AP;

    // Wait for flash ready AND system not in reset before trusting security state.
    // On a WDOG-resetting chip, we need to catch the window where both are true.
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let not_in_reset = (status & MDM_STAT_SYSRES) != 0;
        if fready && not_in_reset {
            break;
        }
        if start.elapsed() > Duration::from_secs(3) {
            tracing::warn!(
                "Kinetis: FREADY+SYSRES not both set after 3s (status: {status:#010x})"
            );
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Score multiple reads, but ONLY count reads where FREADY=1 AND SYSRES=1.
    // Discard reads taken during reset — SYSSEC is unreliable in that state.
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

    tracing::info!(
        "Kinetis security score: {secured_count}/{valid_count} valid reads show SYSSEC"
    );

    if valid_count == 0 {
        // Never got a valid read — system may be stuck in reset.
        // Assume secured as the safe default (will attempt mass erase).
        tracing::warn!("Kinetis: no valid security reads — assuming secured");
        return Ok(true);
    }

    Ok(secured_count > valid_count / 2)
}

/// Halt the Kinetis core via MDM-AP CORE_HOLD_RES + system reset.
///
/// Equivalent to OpenOCD's `kinetis mdm halt` command:
///   1. Set CORE_HOLD_RES — tells the system to hold the core after next reset
///   2. Assert SYS_RES_REQ | CORE_HOLD_RES — trigger a system reset while holding
///   3. Release SYS_RES_REQ, keep CORE_HOLD_RES — system exits reset, core is held
///
/// After this sequence, the core is held at the reset vector and MEM-AP is
/// accessible (the reference manual states: "While [CORE_HOLD_RES] is held,
/// the flash memory is accessible for SWD reads/writes").
///
/// CORE_HOLD_RES remains set — the caller or a later `reset_catch_clear` must
/// release it. The core will remain held until CORE_HOLD_RES is cleared.
fn mdm_halt(iface: &mut dyn DapAccess) -> Result<(), ArmError> {
    let mdm_ap = &MDM_AP;

    tracing::info!("Kinetis: performing MDM halt (CORE_HOLD_RES + system reset)");

    // Step 1: Set CORE_HOLD_RES
    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;

    // Step 2: Assert SYS_RES_REQ + CORE_HOLD_RES (trigger reset with core hold)
    iface.write_raw_ap_register(
        mdm_ap,
        MDM_CONTROL,
        MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
    )?;

    // Wait for system to enter reset (SYSRES=0 means "in reset" per reference manual)
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

    // Step 3: Release SYS_RES_REQ, keep CORE_HOLD_RES
    iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;

    // Wait for system to exit reset (SYSRES=1 means "not in reset")
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

    // Verify core is halted (CORE_HALTED bit in MDM Status)
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_CORE_HALTED) != 0 {
            tracing::info!(
                "Kinetis MDM halt: core halted at reset vector (status: {status:#010x})"
            );
            break;
        }
        if start.elapsed() > Duration::from_millis(500) {
            // Core may not report CORE_HALTED if C_DEBUGEN isn't set yet,
            // but CORE_HOLD_RES still prevents execution. Continue anyway.
            tracing::warn!(
                "Kinetis MDM halt: CORE_HALTED not set (status: {status:#010x}), \
                 but CORE_HOLD_RES should still prevent execution"
            );
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    Ok(())
}

/// Perform the Kinetis mass erase sequence via MDM-AP.
///
/// Algorithm based on OpenOCD's `kinetis.c` and AN4835 Section 4.2.1:
///   1. Wait for FREADY=1 AND system not in reset (SYSRES=1)
///   2. On unsecured chips: assert SYS_RES_REQ first (prevents WDOG during erase)
///   3. Write FMEIP to start mass erase
///   4. Poll until FMEIP reads back as 0 (erase complete)
///   5. On unsecured chips: transition to CORE_HOLD_RES, release SYS_RES_REQ
///
/// On a **secured** chip, only FMEIP is writable in MDM Control (SYS_RES_REQ and
/// CORE_HOLD_RES are NOT writable per reference manual Table 9-5, Secure column).
/// The WDOG continues to run, but the mass erase (~111ms) should complete well
/// within the WDOG timeout (~1.25s).
///
/// After mass erase, the chip is "temporarily unsecured" until POR. The erased flash
/// has FSEC=0xFF (SEC=0b11=secured), but the flash controller's internal "mass erase
/// done" flag overrides this.
fn kinetis_mass_erase(iface: &mut dyn DapAccess, secured: bool) -> Result<(), ArmError> {
    let mdm_ap = &MDM_AP;

    // Pre-check: verify mass erase is enabled
    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    tracing::warn!("Kinetis mass erase: initial MDM Status = {status:#010x}");

    if (status & MDM_STAT_FMEEN) == 0 {
        return Err(ArmDebugSequenceError::custom(
            "Kinetis mass erase is disabled (FMEEN=0). Device may be permanently locked.",
        )
        .into());
    }

    // Wait for FREADY=1 AND system not in reset (SYSRES=1).
    // Both conditions ensure the flash controller is operational and ready.
    // Note: SYSRES=0 means "in reset", SYSRES=1 means "not in reset".
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let not_in_reset = (status & MDM_STAT_SYSRES) != 0;
        if fready && not_in_reset {
            tracing::warn!("Kinetis mass erase: system ready (status: {status:#010x})");
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            return Err(ArmDebugSequenceError::custom(format!(
                "Kinetis flash not ready or system stuck in reset (status: {status:#010x}). \
                 Cannot perform mass erase.",
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    if secured {
        // On a secured chip, only FMEIP (bit 0) is writable in MDM Control.
        // SYS_RES_REQ and CORE_HOLD_RES are NOT writable (Secure=N).
        // Write FMEIP immediately to maximize time before next WDOG reset.
        tracing::warn!("Kinetis mass erase: starting erase (FMEIP only — secured chip)");
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_FMEIP)?;
    } else {
        // On an unsecured chip, assert SYS_RES_REQ to hold the system in reset
        // and prevent WDOG from interfering with the erase.
        tracing::warn!("Kinetis mass erase: asserting system reset + FMEIP");
        iface.write_raw_ap_register(
            mdm_ap,
            MDM_CONTROL,
            MDM_CTRL_SYS_RES_REQ | MDM_CTRL_FMEIP,
        )?;
    }

    // Verify FMEIP was accepted by reading back the control register.
    let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    tracing::warn!(
        "Kinetis mass erase: after write — ctrl={control:#010x}, status={status:#010x}"
    );

    if (control & MDM_CTRL_FMEIP) == 0 {
        return Err(ArmDebugSequenceError::custom(
            "Kinetis: FMEIP not set after write — mass erase request was rejected",
        )
        .into());
    }

    // Wait for erase to complete (FMEIP reads back as 0 in control register).
    // FMEIP is in the debug domain and persists across system resets.
    // FMEACK (status bit 0) would confirm the flash controller started erasing,
    // but it is "cleared after any system reset" — on a secured chip in a WDOG
    // reset loop, FMEACK may never be visible. So we only poll FMEIP.
    // Timeout: 16 seconds for up to 4 pflash blocks (per OpenOCD).
    let start = Instant::now();
    let timeout = Duration::from_secs(16);
    let mut last_log = Instant::now();
    loop {
        let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
        if (control & MDM_CTRL_FMEIP) == 0 {
            tracing::warn!(
                "Kinetis mass erase complete (took {}ms)",
                start.elapsed().as_millis()
            );
            break;
        }
        // Periodic progress logging with full status
        if last_log.elapsed() > Duration::from_secs(2) {
            let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
            let fmeack = if (status & MDM_STAT_FMEACK) != 0 { "yes" } else { "no" };
            tracing::warn!(
                "Kinetis mass erase: waiting — ctrl={control:#010x}, \
                 status={status:#010x}, FMEACK={fmeack}, elapsed={}ms",
                start.elapsed().as_millis()
            );
            last_log = Instant::now();
        }
        if start.elapsed() > timeout {
            let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
            // Do NOT clear MDM_CONTROL here — that would abort an in-progress erase.
            tracing::error!(
                "Timeout waiting for mass erase — ctrl={control:#010x}, status={status:#010x}"
            );
            return Err(ArmError::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }

    if !secured {
        // Unsecured chip: transition to CORE_HOLD_RES before releasing SYS_RES_REQ.
        // This holds the core at the reset vector, preventing the WDOG/reset loop
        // that would otherwise occur with blank flash.
        tracing::warn!("Kinetis mass erase: setting CORE_HOLD_RES before releasing reset");
        iface.write_raw_ap_register(
            mdm_ap,
            MDM_CONTROL,
            MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
        )?;
        // Release SYS_RES_REQ, keep CORE_HOLD_RES
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;
    } else {
        // Secured chip: can't set CORE_HOLD_RES. Clear FMEIP (already cleared by hw).
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, 0)?;
    }

    // Wait for system to come out of reset (SYSRES=1 means "not in reset")
    thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) != 0 {
            tracing::warn!("Kinetis mass erase: system out of reset (status: {status:#010x})");
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

/// Configure debug halt mode via MEM-AP, then release CORE_HOLD_RES.
///
/// Requires CORE_HOLD_RES to be active (from mdm_halt). The core is held
/// at the reset vector with the system out of reset — PPB is accessible via
/// MEM-AP (AHB-AP at AP 0).
///
/// Steps:
///   1. Write DHCSR with C_DEBUGEN (enable debug access)
///   2. Write DEMCR with VC_CORERESET (catch core on reset exit)
///   3. Release CORE_HOLD_RES in MDM Control
///   4. Core exits held state → VC_CORERESET catches it → debug halt
///   5. Verify CORE_HALTED in MDM Status
fn mdm_enter_debug_halt(
    _seq: &Kinetis,
    iface: &mut dyn ArmDebugInterface,
    core_ap: &FullyQualifiedApAddress,
) -> Result<(), ArmError> {
    use crate::architecture::arm::core::armv7m::{Demcr, Dhcsr};

    tracing::info!("Kinetis: configuring debug halt via MEM-AP");

    // Access PPB via MEM-AP to configure debug registers.
    // With CORE_HOLD_RES active, the system is out of reset (SYSRES=1)
    // and PPB (Private Peripheral Bus) is accessible.
    {
        let mut core = iface.memory_interface(core_ap)?;

        // Enable debug in DHCSR
        let mut dhcsr = Dhcsr(0);
        dhcsr.set_c_debugen(true);
        dhcsr.enable_write();
        core.write_word_32(Dhcsr::get_mmio_address(), dhcsr.into())?;

        // Set VC_CORERESET in DEMCR — when CORE_HOLD_RES is released,
        // the core will exit reset and immediately halt via this vector catch.
        let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
        demcr.set_vc_corereset(true);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;

        tracing::debug!("Kinetis: DHCSR.C_DEBUGEN + DEMCR.VC_CORERESET set");
    }

    // Release CORE_HOLD_RES — core exits the held state.
    // With VC_CORERESET set, the core immediately enters debug halt
    // before executing any instructions (even with blank flash).
    iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, 0)?;

    // Wait for CORE_HALTED — confirms the core is in debug halt mode.
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(&MDM_AP, MDM_STATUS)?;
        if (status & MDM_STAT_CORE_HALTED) != 0 {
            tracing::info!(
                "Kinetis: core in debug halt mode (status: {status:#010x})"
            );
            return Ok(());
        }
        if start.elapsed() > Duration::from_millis(500) {
            tracing::warn!(
                "Kinetis: CORE_HALTED not set after releasing CORE_HOLD_RES \
                 (status: {status:#010x})"
            );
            // Even if CORE_HALTED isn't set, the core may still be caught
            // by VC_CORERESET. Continue and let probe-rs try.
            return Ok(());
        }
        thread::sleep(Duration::from_millis(1));
    }
}

impl ArmDebugSequence for Kinetis {
    fn debug_device_unlock(
        &self,
        iface: &mut dyn ArmDebugInterface,
        _default_ap: &FullyQualifiedApAddress,
        permissions: &crate::Permissions,
    ) -> Result<(), ArmError> {
        let mdm_ap = &MDM_AP;

        // Verify MDM-AP identity
        let mdm_idr = iface.read_raw_ap_register(mdm_ap, MDM_IDR)?;
        tracing::info!("Kinetis MDM-AP IDR: {mdm_idr:#010x}");
        if mdm_idr != K_SERIES_MDM_ID {
            tracing::warn!(
                "Unexpected MDM-AP IDR: {mdm_idr:#010x} (expected {K_SERIES_MDM_ID:#010x})"
            );
        }

        // Check security state (with FREADY gating and multi-read scoring)
        if !is_secured(iface)? {
            tracing::info!("Kinetis device is unsecured");

            // Break the WDOG reset loop and put the core in debug halt mode.
            // This follows OpenOCD's `kinetis mdm halt` + `reset halt` approach:
            //
            //   1. mdm_halt() — sets CORE_HOLD_RES, triggers system reset, core is
            //      held at end of reset sequencing (but NOT in debug halt mode)
            //   2. Configure debug via MEM-AP — enable C_DEBUGEN in DHCSR and set
            //      VC_CORERESET in DEMCR (PPB is accessible while core is held)
            //   3. Release CORE_HOLD_RES — core exits reset, VC_CORERESET catches it
            //      and puts it in proper debug halt mode (CORE_HALTED=1)
            //
            // The first MEM-AP access may fail (WDOG timing), so we retry once.
            mdm_halt(iface)?;

            if let Err(e) = mdm_enter_debug_halt(self, iface, _default_ap) {
                tracing::warn!(
                    "Kinetis: first debug halt attempt failed ({e}), retrying mdm_halt"
                );
                mdm_halt(iface)?;
                mdm_enter_debug_halt(self, iface, _default_ap)?;
            }

            return Ok(());
        }

        tracing::warn!("Kinetis device is SECURED. Mass erase will be performed to unlock.");
        permissions
            .erase_all()
            .map_err(|MissingPermissions(desc)| ArmError::MissingPermissions(desc))?;

        kinetis_mass_erase(iface, true)?;

        // Do NOT check SYSSEC here. After mass erase, the erased flash has FSEC=0xFF
        // (SEC=0b11 = secured). The flash controller's "mass erase done" flag should
        // override this to make the chip temporarily unsecured, but the timing of when
        // SYSSEC reflects this is unreliable immediately after reset. Instead, we signal
        // a re-attach — on reconnect, the chip should report as unsecured if the erase
        // succeeded (the "mass erase done" flag persists across warm resets, only cleared
        // by POR).
        tracing::warn!("Kinetis mass erase done. Re-attaching probe.");
        Err(ArmError::ReAttachRequired)
    }

    fn reset_catch_set(
        &self,
        core: &mut dyn ArmMemoryInterface,
        _core_type: crate::CoreType,
        _debug_base: Option<u64>,
    ) -> Result<(), ArmError> {
        use crate::architecture::arm::core::armv7m::{Demcr, Dhcsr};

        // Use the standard Cortex-M VC_CORERESET mechanism to halt on reset.
        // Do NOT use MDM-AP CORE_HOLD_RES here — it holds the core in a
        // "suspended" state where DHCSR.S_HALT is never set, which causes
        // probe-rs to timeout waiting for halt confirmation.
        // VC_CORERESET puts the core in proper debug halt (S_HALT=1).
        let mut demcr = Demcr(core.read_word_32(Demcr::get_mmio_address())?);
        demcr.set_vc_corereset(true);
        core.write_word_32(Demcr::get_mmio_address(), demcr.into())?;

        // Clear status bits by reading DHCSR
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

        let iface = interface.get_arm_debug_interface().map_err(ArmError::from)?;

        // Assert system reset via MDM-AP SYS_RES_REQ.
        // VC_CORERESET (set by reset_catch_set) will catch the core in debug
        // halt when the reset completes, giving S_HALT=1 in DHCSR.
        tracing::debug!("Kinetis: asserting system reset via MDM-AP");
        iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, MDM_CTRL_SYS_RES_REQ)?;

        // Wait for system to enter reset (SYSRES=0 means "in reset")
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

        // Deassert system reset
        iface.write_raw_ap_register(&MDM_AP, MDM_CONTROL, 0)?;

        // Wait for system to come out of reset (SYSRES=1 means "not in reset")
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

        // Re-initialize the debug core after reset.
        // With VC_CORERESET active, the core is now in debug halt (S_HALT=1).
        self.debug_core_start(iface, &core_ap, core_type, debug_base, None)?;

        Ok(())
    }

    fn debug_erase_sequence(&self) -> Option<Arc<dyn DebugEraseSequence>> {
        Some(Arc::new(KinetisEraseSequence))
    }

    fn allowed_access_ports(&self) -> Vec<u8> {
        // AP 0 = MEM-AP (standard memory access)
        // AP 1 = MDM-AP (Kinetis Mass Debug Module)
        vec![0, 1]
    }
}

/// Standalone chip-erase sequence for Kinetis via MDM-AP.
///
/// This can be invoked without a full debug session (e.g. `probe-rs erase`).
#[derive(Debug)]
struct KinetisEraseSequence;

impl DebugEraseSequence for KinetisEraseSequence {
    fn erase_all(&self, interface: &mut dyn ArmDebugInterface) -> Result<(), ArmError> {
        tracing::info!("Kinetis chip erase via MDM-AP");
        let secured = is_secured(interface)?;
        kinetis_mass_erase(interface, secured)?;
        Err(ArmError::ReAttachRequired)
    }
}
