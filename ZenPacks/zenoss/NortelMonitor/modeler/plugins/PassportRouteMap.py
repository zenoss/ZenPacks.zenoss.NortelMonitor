##############################################################################
# 
# Copyright (C) Zenoss, Inc. 2007, 2008, all rights reserved.
# 
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
# 
##############################################################################


__doc__="""PassportRouteMap

PassportRouteMap maps the interface and ip tables to interface objects

"""

from Products.DataCollector.plugins.CollectorPlugin import GetTableMap
from Products.DataCollector.plugins.zenoss.snmp.RouteMap import RouteMap

class PassportRouteMap(RouteMap):
    
    snmpGetTableMaps = (
        # routeTable
        GetTableMap('routetable', '.1.3.6.1.2.1.4.21.1',
                {'.1': 'id',
                 '.2': 'setInterfaceIndex',
                 '.3': 'metric1',
                 '.7': 'setNextHopIp',
                 '.8': 'routetype',
                 '.9': 'routeproto',
                 '.11': 'routemask'}
        ),
        # rcVlanPortTable maps ifIndex to vlanId
        GetTableMap('rcVlanPortTable', '.1.3.6.1.4.1.2272.1.3.3.1',
                {'.6': 'required4bug',
                 '.7': 'vlanIndex'}
        ),
        # rcVlanTable maps vlanId to ifIndex for ipAdEntTable
        GetTableMap('rcVlanTable', '.1.3.6.1.4.1.2272.1.3.2.1',
                {'.6': 'routingIfIndex'}
        ),
    )


    def process(self, device, results, log):
        """collect snmp information from this device"""
        log.info('processing %s for device %s', self.name(), device.id)
        getdata, tabledata = results
        routetable = tabledata.get("routetable")
        porttable = tabledata.get("rcVlanPortTable")
        vlantable = tabledata.get("rcVlanTable")
        localOnly = getattr(device, 'zRouteMapCollectOnlyLocal', False)
        indirectOnly = getattr(device, 'zRouteMapCollectOnlyIndirect', False)

        ifIndexMap = {}
        for ifIndex, portRow in porttable.items():
            vidx = str(portRow['vlanIndex'])
            for vlanIndex, vlanRow in vlantable.items():
                if vlanIndex == vidx:
                    ifIndexMap[vlanRow['routingIfIndex']] = ifIndex

        rm = self.relMap()
        for route in routetable.values():
            om = self.objectMap(route)
            if not hasattr(om, "id"): continue
            if not hasattr(om, "routemask"): continue
            if ifIndexMap.has_key(om.setInterfaceIndex):
                om.setInterfaceIndex = int(ifIndexMap[om.setInterfaceIndex])
            else:
                om.setInterfaceIndex = 0
            om.routemask = self.maskToBits(om.routemask)
            om.setTarget = om.id + "/" + str(om.routemask)
            om.id = om.id + "_" + str(om.routemask)
            if om.routemask == 32: continue
            routeproto = getattr(om, 'routeproto', 'other')
            om.routeproto = self.mapSnmpVal(routeproto, self.routeProtoMap)
            if localOnly and om.routeproto != 'local':
                continue
            if not hasattr(om, 'routetype'): 
                continue    
            om.routetype = self.mapSnmpVal(om.routetype, self.routeTypeMap)
            if indirectOnly and om.routetype != 'indirect':
                continue
            rm.append(om)
        return rm
  
    
    def mapSnmpVal(self, value, map):
        if len(map)+1 >= value:
            value = map[value-1]
        return value


    routeTypeMap = ('other', 'invalid', 'direct', 'indirect')
    routeProtoMap = ('other', 'local', 'netmgmt', 'icmp',
            'egp', 'ggp', 'hello', 'rip', 'is-is', 'es-is',
            'ciscoIgrp', 'bbnSpfIgrp', 'ospf', 'bgp')
