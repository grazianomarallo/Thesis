#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):

    def connect_to_new_network(self, wd):
        devices = wd.list_devices(1);
        self.assertIsNotNone(devices)
        device = devices[0]

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_networks = device.get_ordered_networks()
        ordered_network = ordered_networks[0]

        self.assertEqual(ordered_network.name, "ssidNew")

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def list_removal_and_addition(self, wd):

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 3)

        for network in known_networks:
            if network.name == 'ssidTKIP':
                network.forget()

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 2)

        self.connect_to_new_network(wd)

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 3)

        IWD.copy_to_storage('known_networks/ssidPSK.psk')
        condition = 'len(obj.list_known_networks()) == 4'
        wd.wait_for_object_condition(wd, condition, 1)

        expected = ['ssidNew', 'ssidOpen', 'ssidPSK', 'ssidEAP-TLS']
        self.assertEqual({n.name for n in wd.list_known_networks()},
                         set(expected))

        IWD.remove_from_storage('ssidPSK.psk')
        condition = 'len(obj.list_known_networks()) == 3'
        wd.wait_for_object_condition(wd, condition, 1)

        for net in known_networks:
            net.forget()

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 0)

    def test_known_networks(self):
        wd = IWD(True)

        try:
            self.list_removal_and_addition(wd)
        except:
            del wd
            raise

        del wd

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('known_networks/ssidOpen.open')
        IWD.copy_to_storage('known_networks/ssidTKIP.psk')
        IWD.copy_to_storage('known_networks/ssidEAP-TLS.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
