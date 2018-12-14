#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
from wiphy import wiphy_map

class Test(unittest.TestCase):

    def test_connection_success(self):
        hostapd = None

        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]
            if intf.use == 'hostapd':
                hostapd = HostapdCLI(intf)
                break

        hwsim = Hwsim()
        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1);
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidCCMP")
        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Make AP go down ungracefully, when hostapd comes back up it should
        # send an unprotected disassociate frame so the client will re-auth.
        # This will kick off the SA Query procedure
        hostapd.ungraceful_restart()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # IWD should now try and re-connect to the AP

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
