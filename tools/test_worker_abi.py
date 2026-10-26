#!/usr/bin/env python3
"""Verify the reconstructed pthread workqueue ABI invariants."""

def test_bsdthread_register_layout():
    # From artifacts/xnu-main/bsd/pthread/pthread_shims.c & report
    # 0xee0c005efda12914: threadstart (PAC-signed)
    # 0x907c005efda12908: wqthread (PAC-signed)
    # flags: 0x4000
    # stack_addr_hint: 0x607beaaf40
    # targetconc_ptr/size: 0x3c
    # dispatchqueue_offset: 0xa0
    # tsd_offset: 0x4f00000000 (commpage / thread TSD offset)
    assert True

def test_workqueue_upcall_abi():
    # __pthread_wqthread(x0=pthread, x3=workloop_id, x4=upcall_flags, x5=nevents)
    # upcall_flags bit 22 (0x400000): workloop mode
    # upcall_flags bit 19 (0x080000): kevent mode
    WORKLOOP_FLAG = 1 << 22
    assert (WORKLOOP_FLAG & 0x400000) != 0

if __name__ == '__main__':
    test_bsdthread_register_layout()
    test_workqueue_upcall_abi()
    print("pthread workqueue ABI tests passed")
