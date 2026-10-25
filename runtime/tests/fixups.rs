use hamintosh_runtime::{
    macho::{
        self,
        fixups::{self, Target},
    },
    relocation,
};

const BOOT: &[u8] = include_bytes!("../../tests/fixtures/auth_bootstrap.macho");
const PAYLOAD: usize = 0x8000;
const SEGMENT: usize = PAYLOAD + 28 + 16;

fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn plan(bytes: &[u8]) -> Result<fixups::Plan, String> {
    fixups::parse(bytes, &macho::parse(bytes)?)
}

#[test]
fn arm64e_authentication_uses_relocated_slot_address_and_metadata() {
    let plan = plan(BOOT).unwrap();
    assert_eq!(plan.fixups.len(), 1);
    assert!(plan.imports.is_empty());
    let writes = plan
        .resolve(0x70000000, &[], |target, slot, auth| {
            assert_eq!(target, 0x70001100);
            assert_eq!(slot, 0x70004000);
            assert_eq!(auth.key, 0);
            assert_eq!(auth.diversity, 0x1234);
            assert!(auth.address_diversity);
            Ok(0x123470001100)
        })
        .unwrap();
    assert_eq!(writes, vec![(0x4000, 0x123470001100)]);
}

#[test]
fn decodes_absolute_and_offset_pointer_formats() {
    for format in [1u16, 2, 6, 9, 12] {
        let mut bytes = BOOT.to_vec();
        put16(&mut bytes, SEGMENT + 6, format);
        put64(
            &mut bytes,
            0x4000,
            if [1, 2].contains(&format) {
                0x100001100
            } else {
                0x1100
            },
        );
        let plan = plan(&bytes).unwrap();
        assert!(plan.fixups[0].authentication.is_none());
        assert!(matches!(
            plan.fixups[0].target,
            Target::Rebase {
                offset: 0x1100,
                high8: 0
            }
        ));
        assert_eq!(
            plan.resolve(0x60000000, &[], |_, _, _| panic!("unexpected signer"))
                .unwrap(),
            vec![(0x4000, 0x60001100)]
        );
    }
}

fn bound_fixture(format: u32, weak: bool) -> Vec<u8> {
    let mut bytes = BOOT[..PAYLOAD + 68].to_vec();
    let imports = match format {
        1 => (0xfeu32 | ((weak as u32) << 8)).to_le_bytes().to_vec(),
        2 => [
            (0xfeu32 | ((weak as u32) << 8)).to_le_bytes(),
            (-5i32).to_le_bytes(),
        ]
        .concat(),
        3 => [
            (0xfffeu64 | ((weak as u64) << 16)).to_le_bytes(),
            (-5i64).to_le_bytes(),
        ]
        .concat(),
        _ => unreachable!(),
    };
    put32(&mut bytes, PAYLOAD + 8, 68);
    put32(&mut bytes, PAYLOAD + 12, (68 + imports.len()) as u32);
    put32(&mut bytes, PAYLOAD + 16, 1);
    put32(&mut bytes, PAYLOAD + 20, format);
    bytes.extend(imports);
    bytes.extend(b"_target\0");
    let payload_size = (bytes.len() - PAYLOAD) as u32;
    put64(&mut bytes, 224, payload_size as u64); // __LINKEDIT.fileSize
    put32(&mut bytes, 548, payload_size); // LC_DYLD_CHAINED_FIXUPS.datasize
    put16(&mut bytes, SEGMENT + 6, 6);
    put64(&mut bytes, 0x4000, (1u64 << 63) | (7 << 24));
    bytes
}

#[test]
fn import_ordinals_and_addends_match_all_three_table_formats() {
    for format in [1, 2, 3] {
        let bytes = bound_fixture(format, false);
        let plan = plan(&bytes).unwrap();
        assert_eq!(plan.imports[0].library_ordinal, -2);
        assert_eq!(plan.imports[0].name, "_target");
        assert!(!plan.imports[0].weak);
        assert!(plan
            .resolve(0x60000000, &[], |_, _, _| unreachable!())
            .unwrap_err()
            .contains("_target"));
        let value = if format == 1 { 0x5007 } else { 0x5002 };
        assert_eq!(
            plan.resolve(0x60000000, &[Some(0x5000)], |_, _, _| unreachable!())
                .unwrap(),
            vec![(0x4000, value)]
        );
    }
}

#[test]
fn malformed_chain_offsets_and_imports_cannot_escape_image() {
    for (at, value) in [
        (SEGMENT + 22, 0x3ffc),
        (SEGMENT + 4, 0x2000),
        (SEGMENT + 6, 0xffff),
    ] {
        let mut bytes = BOOT.to_vec();
        put16(&mut bytes, at, value);
        assert!(plan(&bytes).is_err());
    }
    let mut bytes = bound_fixture(1, false);
    put64(&mut bytes, 0x4000, (1u64 << 63) | 1); // bind index 1, only import 0 exists
    assert!(plan(&bytes).is_err());
    for at in PAYLOAD..BOOT.len() {
        let mut bytes = BOOT.to_vec();
        bytes[at] ^= 0xff;
        let _ = plan(&bytes); // malformed metadata must not panic
    }
}

unsafe extern "C" fn test_signer(pointer: u64, _: u64, _: u16, _: u8, _: u8) -> u64 {
    pointer
}

#[test]
fn bootstrap_application_requires_signer_and_resets_for_repeat_launch() {
    let mut mapped = vec![0u8; 0xc000];
    mapped[..BOOT.len()].copy_from_slice(BOOT);
    let original = mapped.clone();
    let mut count = 99;
    let result = unsafe {
        relocation::hm_apply_bootstrap_rebases(
            BOOT.as_ptr(),
            BOOT.len(),
            mapped.as_mut_ptr(),
            mapped.len(),
            None,
            &mut count,
        )
    };
    assert_eq!(result, -5);
    assert_eq!(count, 0);
    assert_eq!(mapped, original);
    for _ in 0..2 {
        assert_eq!(
            unsafe {
                relocation::hm_apply_bootstrap_rebases(
                    BOOT.as_ptr(),
                    BOOT.len(),
                    mapped.as_mut_ptr(),
                    mapped.len(),
                    Some(test_signer),
                    &mut count,
                )
            },
            0
        );
        assert_eq!(count, 1);
        assert_eq!(
            u64::from_le_bytes(mapped[0x4000..0x4008].try_into().unwrap()),
            mapped.as_ptr() as u64 + 0x1100
        );
        assert_eq!(
            unsafe {
                relocation::hm_reset_bootstrap_data(
                    BOOT.as_ptr(),
                    BOOT.len(),
                    mapped.as_mut_ptr(),
                    mapped.len(),
                )
            },
            0
        );
        assert_eq!(mapped, original);
    }
}
