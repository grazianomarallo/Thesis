#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD(True)

        psk_agent = PSKAgent("InvalidSecret")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()

        network = [x for x in ordered_networks if x.name == "ssidSAE"][0]

        self.assertIsNotNone(network)
        self.assertEqual(network.name, "ssidSAE")
        self.assertEqual(network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        with self.assertRaises(iwd.FailedEx):
            network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

        del wd

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
