# -*- coding: utf-8 -*-
import logging
from typing import Dict, List, Tuple, Union, NamedTuple, Optional

from .connection import Connection
from .exceptions import CommandException

_LOGGER = logging.getLogger(__name__)


class Device(NamedTuple):
    mac       : str
    name      : str  | None
    hostname  : str  | None
    ip        : str  | None
    interface : str  | None
    registered: bool | None
    access    : str  | None
    active    : bool | None
    rxbytes   : int  | None
    txbytes   : int  | None
    link      : str  | None


class RouterInfo(NamedTuple):
    name: str
    fw_version: str
    fw_channel: str
    model: str
    hw_version: str
    manufacturer: str
    vendor: str
    region: str
    
    @classmethod
    def from_dict(cls, info: dict) -> "RouterInfo":
        return RouterInfo(
            name=str(info.get('description', info.get('model', 'NDMS2 Router'))),
            fw_version=str(info.get('title', info.get('release'))),
            fw_channel=str(info.get('sandbox', 'unknown')),
            model=str(info.get('model', info.get('hw_id'))),
            hw_version=str(info.get('hw_version', 'N/A')),
            manufacturer=str(info.get('manufacturer')),
            vendor=str(info.get('vendor')),
            region=str(info.get('region', 'N/A')),
        )


class InterfaceInfo(NamedTuple):
    name: str
    type: Optional[str]
    description: Optional[str]
    link: Optional[str]
    connected: Optional[str]
    state: Optional[str]
    mtu: Optional[int]
    address: Optional[str]
    mask: Optional[str]
    uptime: Optional[int]
    security_level: Optional[str]
    mac: Optional[str]

    @classmethod
    def from_dict(cls, info: dict) -> "InterfaceInfo":
        return InterfaceInfo(
            name=InterfaceInfo._str(info.get('interface-name')) or str(info['id']),
            type=InterfaceInfo._str(info.get('type')),
            description=InterfaceInfo._str(info.get('description')),
            link=InterfaceInfo._str(info.get('link')),
            connected=InterfaceInfo._str(info.get('connected')),
            state=InterfaceInfo._str(info.get('state')),
            mtu=InterfaceInfo._int(info.get('mtu')),
            address=InterfaceInfo._str(info.get('address')),
            mask=InterfaceInfo._str(info.get('mask')),
            uptime=InterfaceInfo._int(info.get('uptime')),
            security_level=InterfaceInfo._str(info.get('security-level')),
            mac=InterfaceInfo._str(info.get('mac')),
        )

    @staticmethod
    def _str(value: Optional[any]) -> Optional[str]:
        if value is None:
            return None
        return str(value)


    @staticmethod
    def _int(value: Optional[any]) -> Optional[int]:
        if value is None:
            return None
        return int(value)


class Client(object):
    def __init__(self, connection: Connection):
        self.hotspot: bool = True
        self._connection: Connection = connection


    def get_router_info(self) -> RouterInfo:
        info = self._connection.command_read('/rci/show/version')
        _LOGGER.debug(f'Raw router info: {str(info)}')
        assert isinstance(info, dict), 'Router info response is not a dictionary'
        return RouterInfo.from_dict(info)


    def get_interfaces(self) -> List[InterfaceInfo]:
        interfaces = self._connection.command_read('/rci/show/interface')
        _LOGGER.debug(f'Raw interfaces info: {str(interfaces)}')
        assert isinstance(interfaces, dict), 'Interfaces info response is not a dictionary'
        return [InterfaceInfo.from_dict(info) for info in interfaces.values()]


    def get_interface_info(self, interface_name) -> Optional[InterfaceInfo]:
        info = self._connection.command_read(f'/rci/show/interface?name={interface_name}')
        _LOGGER.debug(f'Raw interface info: {str(info)}')
        assert isinstance(info, dict), 'Interface info response is not a dictionary'
        if 'id' in info:
            return InterfaceInfo.from_dict(info)
        return None


    def get_devices(self) -> List[Device]:
        """Fetches a list of connected devices online"""
        devices = []
        if self.hotspot:
            devices = Client.__merge_devices(devices, self.__get_hotspot_devices())
            if len(devices) > 0:
                return devices
        devices = Client.__merge_devices(devices, self.__get_arp_devices())
        devices = Client.__merge_devices(devices, self.__get_associated_devices())
        return devices


    def get_device_info(self, mac: str) -> Device:
        """Return device info by its mac address."""
        devices = self.get_devices();
        devices = list(filter(lambda dev: dev.mac.upper() == mac.upper(), devices))
        if (len(devices) < 1):
            return None
        return devices[0]


    def register_device(self, mac: str, name: str | None):
        """Registers device (sets known host) in router by its mac address."""
        self.__check_hotspot()
        self.__check_not_none(mac, 'MAC is empty')
        self.__check_not_none(name, 'Name is empty')
        self._connection.command_write('/rci/known/host', {'mac': mac, 'name': name})


    def unregister_device(self, mac: str):
        """Unregister in router previosly registered device by its mac address."""
        self.__check_hotspot()
        self.__check_not_none(mac, 'MAC is empty')
        self._connection.command_delete(f'/rci/known/host?mac={mac}')


    def permit_device_access_to_internet(self, mac: str):
        """Permit access to the internet for previosly registered device."""
        self.__check_hotspot()
        self.__check_not_none(mac, 'MAC is empty')
        device = self.get_device_info(mac)
        self.__check_not_none(device, f'Device witn mac {mac} not found.')
        if device.registered is not True:
            raise CommandException(f'Device witn mac {mac} unregistered. Register it first.')
        self._connection.command_write('/rci/ip/hotspot/host', {'mac': mac, 'access': 'permit'})


    def deny_device_access_to_internet(self, mac: str):
        """Deny access to the internet for previosly registered device."""
        self.__check_hotspot()
        self.__check_not_none(mac, 'MAC is empty')
        device = self.get_device_info(mac)
        self.__check_not_none(device, f'Device witn mac {mac} not found.')
        if device.registered is not True:
            raise CommandException(f'Device witn mac {mac} unregistered. Register it first.')
        self._connection.command_write('/rci/ip/hotspot/host', {'mac': mac, 'access': 'deny'})


    @staticmethod
    def __check_not_none(var, msg: str):
        if var is None:
            raise CommandException(msg)


    def __check_hotspot(self):
        if (self.hotspot is False):
            raise CommandException('Command allowed only for router in hotspot mode.')


    def __get_hotspot_devices(self) -> List[Device]:
        hotspot_info = self.__get_hotspot_info()
        return [Device(
            mac        = info.get('mac').upper(),
            name       = info.get('name', None),
            hostname   = info.get('hostname', None),
            ip         = info.get('ip', None),
            interface  = info['interface'].get('name', None),
            registered = info.get('registered', None),
            access     = info.get('access', None),
            active     = info.get('active', None),
            rxbytes    = info.get('rxbytes', None),
            txbytes    = info.get('txbytes', None),
            link       = info.get('link', None)
        ) for info in hotspot_info.values() if 'interface' in info and info.get('link') == 'up']


    def __get_arp_devices(self) -> List[Device]:
        result = self._connection.command_read('/rci/show/ip/arp')
        return [Device(
            mac        = info.get('mac').upper(),
            name       = info.get('name') or None,
            hostname   = info.get('hostname', None),
            ip         = info.get('ip', None),
            interface  = info.get('interface'),
            registered = info.get('registered', None),
            access     = info.get('access', None),
            active     = info.get('active', None),
            rxbytes    = info.get('rxbytes', None),
            txbytes    = info.get('txbytes', None),
            link       = info.get('link', None)
        ) for info in result if info.get('mac') is not None]


    def __get_associated_devices(self):
        associations = self._connection.command_read('/rci/show/associations')
        items = associations.get('station', [])
        if not isinstance(items, list):
            items = [items]

        aps = set([info.get('ap') for info in items])

        ap_to_bridge = {}
        for ap in aps:
            ap_info = self._connection.command_read(f'/rci/show/interface?name={ap}')
            ap_to_bridge[ap] = ap_info.get('group') or ap_info.get('interface-name')

        # try enriching the results with hotspot additional info
        hotspot_info = self.__get_hotspot_info()

        devices = []

        for info in items:
            mac = info.get('mac')
            if mac is not None and info.get('authenticated') in ['1', 'yes']:
                host_info = hotspot_info.get(mac)
                devices.append(Device(
                    mac        = mac.upper(),
                    name       = host_info.get('name') if host_info else None,
                    hostname   = host_info.get('hostname', None) if host_info else None,
                    ip         = host_info.get('ip') if host_info else None,
                    interface  = ap_to_bridge.get(info.get('ap'), info.get('ap')),
                    registered = host_info.get('registered', None) if host_info else None,
                    access     = host_info.get('access', None) if host_info else None,
                    active     = host_info.get('active', None) if host_info else None,
                    rxbytes    = host_info.get('rxbytes', None) if host_info else None,
                    txbytes    = host_info.get('txbytes', None) if host_info else None,
                    link       = host_info.get('link', None) if host_info else None
                ))

        return devices


    # hotspot info is only available in newest firmware (2.09 and up) and in router mode
    # however missing command error will lead to empty dict returned
    def __get_hotspot_info(self):
        info = self._connection.command_read('/rci/show/ip/hotspot')
        items = info.get('host', [])
        if not isinstance(items, list):
            items = [items]
        return {item.get('mac'): item for item in items}


    @staticmethod
    def __merge_devices(*lists: List[Device]) -> List[Device]:
        res = {}
        for l in lists:
            for dev in l:
                key = (dev.interface, dev.mac)
                if key in res:
                    old_dev = res.get(key)
                    res[key] = Device(
                        mac=old_dev.mac,
                        name=old_dev.name or dev.name,
                        ip=old_dev.ip or dev.ip,
                        interface=old_dev.interface
                    )
                else:
                    res[key] = dev

        return list(res.values())
