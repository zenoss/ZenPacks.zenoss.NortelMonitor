##############################################################################
# 
# Copyright (C) Zenoss, Inc. 2007, 2008, 2009, all rights reserved.
# 
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
# 
##############################################################################


__doc__="""PassportInterfaceMap

PassportInterfaceMap maps Nortel Passport interface tables

"""

import re

from Products.ZenUtils.Utils import cleanstring

from Products.DataCollector.plugins.CollectorPlugin import GetTableMap
from Products.DataCollector.plugins.zenoss.snmp.InterfaceMap import InterfaceMap

class PassportInterfaceMap(InterfaceMap):

    snmpGetTableMaps = (
        # If table
        GetTableMap('iftable', '.1.3.6.1.2.1.2.2.1', 
                {'.1': 'ifindex',
                 '.2': 'id',
                 '.3': 'type',
                 '.4': 'mtu',
                 '.5': 'speed',
                 '.6': 'macaddress',
                 '.7': 'adminStatus',
                 '.8': 'operStatus'}
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
        # ipAddrTable is the better way to get IP addresses
        GetTableMap('ipAddrTable', '.1.3.6.1.2.1.4.20.1',
                {'.1': 'ipAddress',
                 '.2': 'ifindex',
                 '.3': 'netmask'}
        ),
        # Interface Description
        GetTableMap('ifalias', '.1.3.6.1.2.1.31.1.1.1',
                {
                '.6' : 'ifHCInOctets',
                '.7' : 'ifHCInUcastPkts',
                '.18' : 'description',
                '.15' : 'highSpeed',
                }
        ),

    )

   
    def process(self, device, results, log):
        """collect snmp information from this device"""
        getdata, tabledata = results
        log.info('processing %s for device %s', self.name(), device.id)
        rm = self.relMap()
        iptable = tabledata.get("ipAddrTable")
        porttable = tabledata.get("rcVlanPortTable")
        vlantable = tabledata.get("rcVlanTable")
        iftable = tabledata.get("iftable")
        ifalias = tabledata.get("ifalias")
        if iptable is None or iftable is None: return
        if not ifalias: ifalias = {}

        # add interface alias (cisco description) to iftable
        for ifidx, data in ifalias.items():
            if not iftable.has_key(ifidx): continue
            iftable[ifidx]['description'] = data.get('description', '')
            # handle 10GB interfaces using IF-MIB::ifHighSpeed
            speed = iftable[ifidx].get('speed',0)
            if speed == 4294967295L or speed < 0:
                try: iftable[ifidx]['speed'] = data['highSpeed']*1e6
                except KeyError: pass

            # Detect availability of the high-capacity counters
            if data.get('ifHCInOctets', None) is not None: # and \
               # data.get('ifHCInUcastPkts', None) is not None:
                iftable[ifidx]['hcCounters'] = True

        if iptable is None or iftable is None or porttable is None \
                or vlantable is None: return

        ifIndexMap = {}
        for ifIndex, portRow in porttable.items():
            vidx = str(portRow['vlanIndex'])
            for vlanIndex, vlanRow in vlantable.items():
                if vlanIndex == vidx:
                    ifIndexMap[vlanRow['routingIfIndex']] = ifIndex

        omtable = {}
        for ip, row in iptable.items():
            if not ifIndexMap.has_key(row['ifindex']): continue
            strindex = str(ifIndexMap[row['ifindex']])
            if not omtable.has_key(strindex) and not iftable.has_key(strindex):
                log.warn("skipping %s points to missing ifindex %s",
                            row.get('ipAddress',""), row.get('ifindex',""))
                continue                                 
            if not omtable.has_key(strindex):
                om = self.processInt(log, device, iftable[strindex])
                if not om: continue
                rm.append(om)
                omtable[strindex] = om
                del iftable[strindex]
            elif omtable.has_key(strindex): 
                om = omtable[strindex]
            else:
                log.warn("ip points to missing ifindex %s skipping", strindex) 
                continue
            if not hasattr(om, 'setIpAddresses'): om.setIpAddresses = []
            if row.has_key('ipAddress'): ip = row['ipAddress']
            ip = ip + "/" + str(self.maskToBits(row['netmask'].strip()))
            om.setIpAddresses.append(ip)

        for iface in iftable.values():
            om = self.processInt(log, device, iface)
            if om: rm.append(om)
        return rm
