#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
from wiphy import wiphy_map
import testutil

class Test(unittest.TestCase):
    def test_preauth_success(self):
        hwsim = Hwsim()

        bss_hostapd = [None, None]
        bss_radio = [None, None]
        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]
            if intf.config and '1' in intf.config:
                bss_idx = 0
            elif intf.config and '2' in intf.config:
                bss_idx = 1
            else:
                continue

            for path in hwsim.radios:
                radio = hwsim.radios[path]
                if radio.name == wname:
                    break

            bss_hostapd[bss_idx] = HostapdCLI(intf)
            bss_radio[bss_idx] = radio

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True

        # Fill in the neighbor AP tables in both BSSes.  By default each
        # instance knows only about current BSS, even inside one hostapd
        # process.
        # Roaming still works without the neighbor AP table but neighbor
        # reports have to be disabled in the .conf files
        bss0_nr = ''.join(bss_radio[0].addresses[0].split(':')) + \
                '8f0000005101060603000000'
        bss1_nr = ''.join(bss_radio[1].addresses[0].split(':')) + \
                '8f0000005102060603000000'

        bss_hostapd[0].set_neighbor(bss_radio[1].addresses[0], 'TestPreauth',
                bss1_nr)
        bss_hostapd[1].set_neighbor(bss_radio[0].addresses[0], 'TestPreauth',
                bss0_nr)

        wd = IWD()

        device = wd.list_devices(1)[0];

        # Check that iwd selects BSS 0 first
        rule0.signal = -2500
        rule1.signal = -3500

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        self.assertEqual(len(ordered_networks), 1)
        ordered_network = ordered_networks[0]
        self.assertEqual(ordered_network.name, "TestPreauth")
        self.assertEqual(ordered_network.type, NetworkType.eap)
        self.assertEqual(ordered_network.signal_strength, -2500)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertTrue(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          bss_hostapd[1].ifname, device.name)

        # Check that iwd starts transition to BSS 1 in less than 15 seconds
        rule0.signal = -8000

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition, 15)

        # TODO: verify that the PMK from preauthentication was used

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        condition = 'obj.state != DeviceState.roaming'
        wd.wait_for_object_condition(device, condition, 5)

        self.assertEqual(device.state, iwd.DeviceState.connected)
        self.assertTrue(bss_hostapd[1].list_sta())

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (bss_hostapd[0].ifname, device.name))

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestPreauth.8021x')

        os.system('ifconfig lo up')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
