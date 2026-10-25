use harmintosh_runtime::{hm_probe_plan, hm_validate_aot_image, macho, ProbePlan};

const PROBE: &[u8] = include_bytes!("../../tests/fixtures/return42.macho");

fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

#[test]
fn locates_entry_and_builds_audited_execution_plan() {
    let image = macho::parse(PROBE).unwrap();
    assert_eq!(image.entry_vm_address, Some(0x100001000));
    assert_eq!(image.segments[0].protection, 5);
    let mut plan = ProbePlan::default();
    assert_eq!(
        unsafe { hm_probe_plan(PROBE.as_ptr(), PROBE.len(), &mut plan) },
        0
    );
    assert_eq!(plan.entry_offset, 0x1000);
}

#[test]
fn all_truncated_prefixes_fail_without_panicking() {
    for len in 0..PROBE.len() {
        assert!(macho::parse(&PROBE[..len]).is_err(), "length {len}");
    }
}

#[test]
fn rejects_command_escape_and_entry_in_headers_or_data() {
    for (offset, value) in [(36, 0xfffffff8), (16, u32::MAX), (20, u32::MAX)] {
        let mut bytes = PROBE.to_vec();
        put32(&mut bytes, offset, value);
        assert!(macho::parse(&bytes).is_err());
    }
    for entry in [0, 4, 0x1001, PROBE.len() as u64, u64::MAX] {
        let mut bytes = PROBE.to_vec();
        put64(&mut bytes, 112, entry);
        assert!(macho::parse(&bytes).is_err());
    }
}

#[test]
fn rejects_unaudited_code_at_execution_boundary() {
    let mut bytes = PROBE.to_vec();
    bytes[4096] ^= 1;
    assert!(macho::parse(&bytes).is_ok());
    assert_eq!(
        unsafe { hm_probe_plan(bytes.as_ptr(), bytes.len(), &mut ProbePlan::default()) },
        -5
    );
}

#[test]
fn selects_arm64_universal_slice_and_checks_bounds() {
    for wide in [false, true] {
        let mut bytes = vec![0u8; 0x1000];
        bytes[..4].copy_from_slice(if wide {
            &[0xca, 0xfe, 0xba, 0xbf]
        } else {
            &[0xca, 0xfe, 0xba, 0xbe]
        });
        bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
        bytes[8..12].copy_from_slice(&0x0100000cu32.to_be_bytes());
        if wide {
            bytes[16..24].copy_from_slice(&0x1000u64.to_be_bytes());
            bytes[24..32].copy_from_slice(&(PROBE.len() as u64).to_be_bytes());
        } else {
            bytes[16..20].copy_from_slice(&0x1000u32.to_be_bytes());
            bytes[20..24].copy_from_slice(&(PROBE.len() as u32).to_be_bytes());
        }
        bytes.extend_from_slice(PROBE);
        assert_eq!(macho::parse(&bytes).unwrap().slice_offset, 0x1000);
        let mut plan = ProbePlan::default();
        assert_eq!(
            unsafe { hm_probe_plan(bytes.as_ptr(), bytes.len(), &mut plan) },
            0
        );
        assert_eq!(plan.slice_offset, 0x1000);
        bytes.pop();
        assert!(macho::parse(&bytes).is_err());
    }
}

#[test]
fn arbitrary_header_mutations_do_not_panic() {
    for i in 0..128 {
        for n in [0, 0x7f, 0x80, 0xff] {
            let mut bytes = PROBE.to_vec();
            bytes[i] = n;
            let _ = macho::parse(&bytes);
        }
    }
}

#[test]
fn arm64e_cannot_enter_audited_arm64_probe() {
    let mut bytes = PROBE.to_vec();
    put32(&mut bytes, 8, 0x80000002);
    assert!(macho::parse(&bytes).is_ok());
    assert_eq!(
        unsafe { hm_probe_plan(bytes.as_ptr(), bytes.len(), &mut ProbePlan::default()) },
        -3
    );
}

#[test]
fn checks_aot_mapping_before_any_app_entry_can_be_considered() {
    let mut mapped = vec![0u8; 0x4000];
    mapped[..PROBE.len()].copy_from_slice(PROBE);
    let mut entry = 0;
    assert_eq!(
        unsafe {
            hm_validate_aot_image(
                PROBE.as_ptr(),
                PROBE.len(),
                mapped.as_ptr(),
                mapped.len(),
                &mut entry,
            )
        },
        0
    );
    assert_eq!(entry, 0x1000);
    mapped[0x1000] ^= 1;
    assert_eq!(
        unsafe {
            hm_validate_aot_image(
                PROBE.as_ptr(),
                PROBE.len(),
                mapped.as_ptr(),
                mapped.len(),
                &mut entry,
            )
        },
        -5
    );
    assert_eq!(
        unsafe {
            hm_validate_aot_image(
                PROBE.as_ptr(),
                PROBE.len(),
                mapped.as_ptr(),
                0x1000,
                &mut entry,
            )
        },
        -4
    );
}

fn unixthread_fixture() -> Vec<u8> {
    let mut bytes = PROBE.to_vec();
    put32(&mut bytes, 12, 7); // MH_DYLINKER
    put32(&mut bytes, 20, 72 + 288);
    bytes[104..392].fill(0);
    put32(&mut bytes, 104, 5); // LC_UNIXTHREAD
    put32(&mut bytes, 108, 288);
    put32(&mut bytes, 112, 6); // ARM_THREAD_STATE64
    put32(&mut bytes, 116, 68);
    put64(&mut bytes, 120 + 256, 0x100001000);
    bytes
}

#[test]
fn finds_dyld_entry_in_arm_thread_state64() {
    let bytes = unixthread_fixture();
    let image = macho::parse(&bytes).unwrap();
    assert_eq!(image.entry_command, Some("LC_UNIXTHREAD"));
    assert_eq!(image.entry_file_offset, Some(0x1000));
    assert_eq!(image.entry_vm_address, Some(0x100001000));
}

#[test]
fn rejects_invalid_thread_state_sizes_and_pc() {
    for count in [0, 67, 69, u32::MAX] {
        let mut bytes = unixthread_fixture();
        put32(&mut bytes, 116, count);
        assert!(macho::parse(&bytes).is_err());
    }
    for pc in [0, 0x100000000, 0x100001001, 0x100004000, u64::MAX] {
        let mut bytes = unixthread_fixture();
        put64(&mut bytes, 120 + 256, pc);
        assert!(macho::parse(&bytes).is_err());
    }
}
