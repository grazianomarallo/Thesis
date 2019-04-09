/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2013-2018  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <linux/if_ether.h>

#include <ell/ell.h>

#include "src/iwd.h"
#include "src/util.h"
#include "src/wiphy.h"
#include "src/scan.h"
#include "src/netdev.h"
#include "src/dbus.h"
#include "src/station.h"
#include "src/device.h"

struct device {
	uint32_t index;

	struct wiphy *wiphy;
	struct netdev *netdev;

	bool powered : 1;		/* Current IFUP state */
	bool dbus_powered : 1;		/* Last IFUP state wanted via D-Bus */

	uint32_t ap_roam_watch;
	uint32_t wiphy_rfkill_watch;
};

static uint32_t netdev_watch;

static void device_ap_roam_frame_event(struct netdev *netdev,
		const struct mmpdu_header *hdr,
		const void *body, size_t body_len,
		void *user_data)
{
	struct device *device = user_data;
	struct station *station = station_find(device->index);

	if (!station)
		return;

	station_ap_directed_roam(station, hdr, body, body_len);
}

static bool device_property_get_name(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 's',
					netdev_get_name(device->netdev));
	return true;
}

static bool device_property_get_address(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	const char *str;

	str = util_address_to_string(netdev_get_address(device->netdev));
	l_dbus_message_builder_append_basic(builder, 's', str);

	return true;
}

static bool device_property_get_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool powered = device->powered;

	l_dbus_message_builder_append_basic(builder, 'b', &powered);

	return true;
}

struct set_generic_cb_data {
	struct device *device;
	struct l_dbus *dbus;
	struct l_dbus_message *message;
	l_dbus_property_complete_cb_t complete;
};

static void set_generic_destroy(void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;

	/* Message hasn't been replied to, generate an Aborted error */
	if (cb_data->message)
		cb_data->complete(cb_data->dbus, cb_data->message,
					dbus_error_aborted(cb_data->message));

	l_free(cb_data);
}

static void set_powered_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_failed(cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
	cb_data->message = NULL;
}

static struct l_dbus_message *device_property_set_powered(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct device *device = user_data;
	bool powered;
	struct set_generic_cb_data *cb_data;
	int r;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &powered))
		return dbus_error_invalid_args(message);

	device->dbus_powered = powered;

	if (powered == device->powered) {
		complete(dbus, message, NULL);

		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	r = netdev_set_powered(device->netdev, powered, set_powered_cb,
					cb_data, set_generic_destroy);
	if (r < 0) {
		l_free(cb_data);
		return dbus_error_from_errno(r, message);
	}

	return NULL;
}

static bool device_property_get_4addr(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	bool use_4addr = netdev_get_4addr(device->netdev);

	l_dbus_message_builder_append_basic(builder, 'b', &use_4addr);

	return true;
}

static void set_4addr_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_failed(cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
	cb_data->message = NULL;

	l_dbus_property_changed(cb_data->dbus,
				netdev_get_path(cb_data->device->netdev),
				IWD_DEVICE_INTERFACE, "WDS");
}

static struct l_dbus_message *device_property_set_4addr(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct set_generic_cb_data *cb_data;
	struct device *device = user_data;
	bool use_4addr;

	if (!l_dbus_message_iter_get_variant(new_value, "b", &use_4addr))
		return dbus_error_invalid_args(message);

	if (use_4addr == netdev_get_4addr(device->netdev)) {
		complete(dbus, message, NULL);

		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	if (netdev_set_4addr(device->netdev, use_4addr, set_4addr_cb,
				cb_data, set_generic_destroy) < 0)
		return dbus_error_failed(message);

	return NULL;
}

static bool device_property_get_adapter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;

	l_dbus_message_builder_append_basic(builder, 'o',
					wiphy_get_path(device->wiphy));

	return true;
}

static bool device_property_get_mode(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct device *device = user_data;
	uint32_t iftype = netdev_get_iftype(device->netdev);
	const char *modestr = dbus_iftype_to_string(iftype);

	if (modestr == NULL)
		modestr = "unknown";

	l_dbus_message_builder_append_basic(builder, 's', modestr);

	return true;
}

static void set_mode_cb(struct netdev *netdev, int result, void *user_data)
{
	struct set_generic_cb_data *cb_data = user_data;
	struct l_dbus_message *reply = NULL;

	if (result < 0)
		reply = dbus_error_from_errno(result, cb_data->message);

	cb_data->complete(cb_data->dbus, cb_data->message, reply);
	cb_data->message = NULL;

	l_dbus_property_changed(cb_data->dbus,
				netdev_get_path(cb_data->device->netdev),
				IWD_DEVICE_INTERFACE, "Mode");
}

static struct l_dbus_message *device_property_set_mode(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	struct device *device = user_data;
	struct netdev *netdev = device->netdev;
	const char *mode;
	enum netdev_iftype iftype;
	int r;
	struct set_generic_cb_data *cb_data;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &mode))
		return dbus_error_invalid_args(message);

	if (!strcmp(mode, "station"))
		iftype = NETDEV_IFTYPE_STATION;
	else if (!strcmp(mode, "ap"))
		iftype = NETDEV_IFTYPE_AP;
	else if (!strcmp(mode, "ad-hoc"))
		iftype = NETDEV_IFTYPE_ADHOC;
	else
		return dbus_error_invalid_args(message);

	if (iftype == netdev_get_iftype(netdev)) {
		complete(dbus, message, NULL);
		return NULL;
	}

	cb_data = l_new(struct set_generic_cb_data, 1);
	cb_data->device = device;
	cb_data->dbus = dbus;
	cb_data->message = message;
	cb_data->complete = complete;

	r = netdev_set_iftype(device->netdev, iftype, set_mode_cb,
					cb_data, set_generic_destroy);
	if (r < 0) {
		l_free(cb_data);
		return dbus_error_from_errno(r, message);
	}

	return NULL;
}

static void setup_device_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "Name", 0, "s",
					device_property_get_name, NULL);
	l_dbus_interface_property(interface, "Address", 0, "s",
					device_property_get_address, NULL);
	l_dbus_interface_property(interface, "WDS", 0, "b",
					device_property_get_4addr,
					device_property_set_4addr);
	l_dbus_interface_property(interface, "Powered", 0, "b",
					device_property_get_powered,
					device_property_set_powered);
	l_dbus_interface_property(interface, "Adapter", 0, "o",
					device_property_get_adapter, NULL);
	l_dbus_interface_property(interface, "Mode", 0, "s",
					device_property_get_mode,
					device_property_set_mode);
}

static void device_netdev_notify(struct netdev *netdev,
					enum netdev_watch_event event,
					void *user_data)
{
	struct device *device = netdev_get_device(netdev);
	struct l_dbus *dbus = dbus_get_bus();

	if (!device)
		return;

	switch (event) {
	case NETDEV_WATCH_EVENT_UP:
		device->powered = true;

		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Powered");
		break;
	case NETDEV_WATCH_EVENT_DOWN:
		device->powered = false;

		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Powered");
		break;
	case NETDEV_WATCH_EVENT_NAME_CHANGE:
		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Name");
		break;
	case NETDEV_WATCH_EVENT_ADDRESS_CHANGE:
		l_dbus_property_changed(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, "Address");
		break;
	default:
		break;
	}
}

static void device_wiphy_state_changed_event(struct wiphy *wiphy,
					enum wiphy_state_watch_event event,
					void *user_data)
{
	struct device *device = user_data;

	switch (event) {
	case WIPHY_STATE_WATCH_EVENT_RFKILLED:
		break;
	case WIPHY_STATE_WATCH_EVENT_POWERED:
		if (device->dbus_powered)
			netdev_set_powered(device->netdev, true,
							NULL, NULL, NULL);
		break;
	}
}

struct device *device_create(struct wiphy *wiphy, struct netdev *netdev)
{
	struct device *device;
	struct l_dbus *dbus = dbus_get_bus();
	uint32_t ifindex = netdev_get_ifindex(netdev);
	const uint8_t action_ap_roam_prefix[2] = { 0x0a, 0x07 };

	device = l_new(struct device, 1);
	device->index = ifindex;
	device->wiphy = wiphy;
	device->netdev = netdev;

	if (!l_dbus_object_add_interface(dbus, netdev_get_path(device->netdev),
					IWD_DEVICE_INTERFACE, device))
		l_info("Unable to register %s interface", IWD_DEVICE_INTERFACE);

	if (!l_dbus_object_add_interface(dbus, netdev_get_path(device->netdev),
					L_DBUS_INTERFACE_PROPERTIES, device))
		l_info("Unable to register %s interface",
				L_DBUS_INTERFACE_PROPERTIES);

	scan_ifindex_add(device->index);

	/*
	 * register for AP roam transition watch
	 */
	device->ap_roam_watch = netdev_frame_watch_add(netdev, 0x00d0,
			action_ap_roam_prefix, sizeof(action_ap_roam_prefix),
			device_ap_roam_frame_event, device);

	device->powered = netdev_get_is_up(netdev);

	device->dbus_powered = true;
	device->wiphy_rfkill_watch =
		wiphy_state_watch_add(wiphy, device_wiphy_state_changed_event,
					device, NULL);

	return device;
}

void device_remove(struct device *device)
{
	struct l_dbus *dbus = dbus_get_bus();

	l_debug("");

	l_dbus_unregister_object(dbus, netdev_get_path(device->netdev));

	scan_ifindex_remove(device->index);

	netdev_frame_watch_remove(device->netdev, device->ap_roam_watch);
	wiphy_state_watch_remove(device->wiphy, device->wiphy_rfkill_watch);

	l_free(device);
}

bool device_init(void)
{
	if (!l_dbus_register_interface(dbus_get_bus(),
					IWD_DEVICE_INTERFACE,
					setup_device_interface,
					NULL, false))
		return false;

	netdev_watch = netdev_watch_add(device_netdev_notify, NULL, NULL);

	return true;
}

void device_exit(void)
{
	netdev_watch_remove(netdev_watch);

	l_dbus_unregister_interface(dbus_get_bus(), IWD_DEVICE_INTERFACE);
}