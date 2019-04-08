#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType

class Test(unittest.TestCase):

    def run_connection_test(self, ssid, *secrets):
        wd = IWD()

        psk_agent = iwd.PSKAgent(*secrets)
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1);
        device = devices[0]

        try:
            device.disconnect()
        except:
            pass

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        if not device.get_ordered_networks():
            device.scan()
            condition = 'obj.scanning'
            wd.wait_for_object_condition(device, condition)
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

        network = None
        for ordered_network in device.get_ordered_networks():
            if ordered_network.name == ssid:
                network = ordered_network
                break
        self.assertEqual(network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_agent_none(self):
        self.run_connection_test('ssidEAP-MSCHAPV2-1')

    def test_agent_none_hash(self):
        self.run_connection_test('ssidEAP-MSCHAPV2-2')

    def test_agent_passwd(self):
        self.run_connection_test('ssidEAP-MSCHAPV2-3', [], ('domain\\User', 'Password'))

    def test_agent_username_and_passwd(self):
        self.run_connection_test('ssidEAP-MSCHAPV2-4', [], ('domain\\User', 'Password'))

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-MSCHAPV2-1.8021x')
        IWD.copy_to_storage('ssidEAP-MSCHAPV2-2.8021x')
        IWD.copy_to_storage('ssidEAP-MSCHAPV2-3.8021x')
        IWD.copy_to_storage('ssidEAP-MSCHAPV2-4.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
