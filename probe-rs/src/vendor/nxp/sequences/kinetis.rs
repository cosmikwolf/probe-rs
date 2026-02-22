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

use crate::architecture::arm::{
    ArmDebugInterface, ArmError, DapAccess, FullyQualifiedApAddress,
    memory::ArmMemoryInterface,
    sequences::{ArmDebugSequence, ArmDebugSequenceError, DebugEraseSequence},
};
use crate::session::MissingPermissions;
use crate::MemoryMappedRegister;

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
            tracing::warn!(
                "Kinetis: FREADY+SYSRES not both set after 3s (status: {status:#010x})"
            );
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
            // CORE_HOLD_RES still prevents execution. mdm_enter_debug_halt
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
/// On secured chips, only FMEIP is writable (Table 9-5). On unsecured chips,
/// SYS_RES_REQ is asserted first to prevent WDOG interference. After erase,
/// the flash controller's "mass erase done" flag overrides FSEC security until POR.
fn kinetis_mass_erase(iface: &mut dyn DapAccess, secured: bool) -> Result<(), ArmError> {
    let mdm_ap = &MDM_AP;

    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    tracing::debug!("Kinetis mass erase: initial MDM Status = {status:#010x}");

    if (status & MDM_STAT_FMEEN) == 0 {
        return Err(ArmDebugSequenceError::custom(
            "Kinetis mass erase is disabled (FMEEN=0). Device may be permanently locked.",
        )
        .into());
    }

    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        let fready = (status & MDM_STAT_FREADY) != 0;
        let not_in_reset = (status & MDM_STAT_SYSRES) != 0;
        if fready && not_in_reset {
            tracing::debug!("Kinetis mass erase: system ready (status: {status:#010x})");
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
        tracing::info!("Kinetis mass erase: starting erase (FMEIP only — secured chip)");
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_FMEIP)?;
    } else {
        tracing::info!("Kinetis mass erase: starting erase (SYS_RES_REQ + FMEIP)");
        iface.write_raw_ap_register(
            mdm_ap,
            MDM_CONTROL,
            MDM_CTRL_SYS_RES_REQ | MDM_CTRL_FMEIP,
        )?;
    }

    let control = iface.read_raw_ap_register(mdm_ap, MDM_CONTROL)?;
    let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
    tracing::debug!(
        "Kinetis mass erase: after write — ctrl={control:#010x}, status={status:#010x}"
    );

    if (control & MDM_CTRL_FMEIP) == 0 {
        return Err(ArmDebugSequenceError::custom(
            "Kinetis: FMEIP not set after write — mass erase request was rejected",
        )
        .into());
    }

    // Poll FMEIP (not FMEACK — FMEACK is cleared by system resets, unreliable on
    // secured chips in a WDOG reset loop). 16s timeout per OpenOCD.
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
            let fmeack = if (status & MDM_STAT_FMEACK) != 0 { "yes" } else { "no" };
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
            return Err(ArmError::Timeout);
        }
        thread::sleep(Duration::from_millis(50));
    }

    if !secured {
        // Hold core before releasing reset to prevent WDOG loop on blank flash.
        iface.write_raw_ap_register(
            mdm_ap,
            MDM_CONTROL,
            MDM_CTRL_SYS_RES_REQ | MDM_CTRL_CORE_HOLD_RES,
        )?;
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, MDM_CTRL_CORE_HOLD_RES)?;
    } else {
        iface.write_raw_ap_register(mdm_ap, MDM_CONTROL, 0)?;
    }

    thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    loop {
        let status = iface.read_raw_ap_register(mdm_ap, MDM_STATUS)?;
        if (status & MDM_STAT_SYSRES) != 0 {
            tracing::debug!("Kinetis mass erase: system out of reset (status: {status:#010x})");
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

/// Set C_DEBUGEN + VC_CORERESET via MEM-AP, then release CORE_HOLD_RES.
///
/// Requires CORE_HOLD_RES active (from `mdm_halt`). The core exits the held
/// state and immediately halts via VC_CORERESET, giving proper S_HALT=1.
fn mdm_enter_debug_halt(
    _seq: &Kinetis,
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
            tracing::debug!(
                "Kinetis: core in debug halt mode (status: {status:#010x})"
            );
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
    core.write_word_32(DCRSR, (1 << 16) | 0)?; // R0
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
        tracing::warn!(
            "Kinetis WDOG disable may have failed (STCTRLH = {stctrlh:#06x})"
        );
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

        let iface = interface.get_arm_debug_interface().map_err(ArmError::from)?;

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
        mdm_halt(interface)?;
        let secured = is_secured(interface)?;
        kinetis_mass_erase(interface, secured)?;
        Err(ArmError::ReAttachRequired)
    }
}
