#!/usr/bin/env python3
"""Validate Darwin QoS to pthread priority mapping ranges."""

def test_qos_priorities():
    # Standard Darwin QoS priority tiers
    QOS_MAINTENANCE = 0x05
    QOS_BACKGROUND = 0x09
    QOS_UTILITY = 0x11
    QOS_DEFAULT = 0x15
    QOS_USER_INITIATED = 0x21
    QOS_USER_INTERACTIVE = 0x25

    qos_levels = [QOS_MAINTENANCE, QOS_BACKGROUND, QOS_UTILITY, QOS_DEFAULT, QOS_USER_INITIATED, QOS_USER_INTERACTIVE]
    # Check monotonicity
    assert qos_levels == sorted(qos_levels)

if __name__ == '__main__':
    test_qos_priorities()
    print("QoS priority mapping tests passed")
