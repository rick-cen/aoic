#!/usr/bin/env python3
import sys
sys.path.insert(0, '/opt/bacpypes_modern')  # Forces Python to load the new version

import time
import logging
from datetime import datetime

# Core stable bacpypes engine modules
from bacpypes.core import run, stop
from bacpypes.local.device import LocalDeviceObject
from bacpypes.app import BIPSimpleApplication  

# Comprehensive object definitions matching the simulation profile
from bacpypes.object import (
    AnalogInputObject, AnalogOutputObject, AnalogValueObject,
    BinaryInputObject, BinaryOutputObject, BinaryValueObject,
    CommandObject, IntegerValueObject, NotificationClassObject,
    MultiStateInputObject, MultiStateOutputObject, MultiStateValueObject,
    ScheduleObject, AccumulatorObject, NetworkPortObject, 
    CharacterStringValueObject, OctetStringValueObject, PositiveIntegerValueObject,
    TrendLogObject, LightingOutputObject, ChannelObject, LifeSafetyPointObject,
    LoadControlObject
)
from bacpypes.basetypes import StatusFlags

class BACHoneypot(BIPSimpleApplication):
    def __init__(self, *args, **kwargs):
        super(BACHoneypot, self).__init__(*args, **kwargs)
        self.alert_cache = {}
        self.y2k38_triggered = False  

    def indication(self, apdu):
        source_address = getattr(apdu, 'pduSource', 'UnknownIP:0')
        request_type = apdu.__class__.__name__
        current_time = time.time()
        
        cache_key = f"{source_address}_{request_type}"
        
        # Rate-limiting: suppress duplicate service requests for 5 seconds
        if cache_key not in self.alert_cache or (current_time - self.alert_cache[cache_key]) > 5:
            self.alert_cache[cache_key] = current_time
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            service_id = f" ID:{apdu.serviceChoice}" if hasattr(apdu, 'serviceChoice') else ""
            
            print(f"INFO:honeypot.bacnet:{timestamp} - Request from {source_address} -> {request_type}{service_id}")

        super(BACHoneypot, self).indication(apdu)

    def do_TimeSynchronizationRequest(self, apdu):
        source_address = getattr(apdu, 'pduSource', 'UnknownIP:0')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        
        if hasattr(apdu, 'time') and hasattr(apdu, 'date'):
            sync_year = apdu.date.value[0] + 1900  
            print(f"INFO:honeypot.bacnet:{timestamp} - TimeSync Request received from {source_address} targeting Year: {sync_year}")
            
            if sync_year >= 2038 and not self.y2k38_triggered:
                print(f"CRITICAL:honeypot.scada:{timestamp} - 32-bit Signed Integer Overflow (Y2K38 Wrap-Around Event)!")
                print(f"CRITICAL:honeypot.scada:{timestamp} - System Epoch fault: Forcing critical system failure state parameters.")
                self.y2k38_triggered = True
                self._trigger_input_wipe()

        super(BACHoneypot, self).do_TimeSynchronizationRequest(apdu)

    def do_WritePropertyRequest(self, apdu):
        source_address = getattr(apdu, 'pduSource', 'UnknownIP:0')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        
        obj_type, obj_inst = apdu.objectIdentifier
        prop_id = apdu.propertyIdentifier
        
        try:
            new_value = apdu.propertyValue.cast_out()
        except Exception:
            new_value = "Unparseable raw payload"
            
        print(f"INFO:honeypot.bacnet:{timestamp} - Write request from {source_address} to {obj_type}:{obj_inst} | Property: {prop_id} | Value: {new_value}")
        
        super(BACHoneypot, self).do_WritePropertyRequest(apdu)

    def _trigger_input_wipe(self):
        """Simulates an unhandled system exception by scrambling and faulting parameters."""
        for obj_id, obj in self.objectName.items(): 
            # Force analog telemetry to severe error ceilings
            if isinstance(obj, AnalogInputObject):
                obj.presentValue = 999.9
                obj.statusFlags = StatusFlags([0, 1, 0, 1])  # Fault & Out Of Service bits TRUE
                
            # Trip every physical input sensor to alarm conditions
            elif isinstance(obj, BinaryInputObject):
                obj.presentValue = 1 if obj.presentValue == 0 else 0
                obj.statusFlags = StatusFlags([0, 1, 0, 0])  # Fault bit TRUE
                
            # Overflow the totalizer registers
            elif isinstance(obj, AccumulatorObject):
                obj.presentValue = 9999999
                obj.statusFlags = StatusFlags([0, 1, 0, 0])
                
            # Change the active SCADA routing key to indicate system corruption
            elif isinstance(obj, CharacterStringValueObject) and obj.objectName == 'STR_VAL_01':
                obj.presentValue = 'ERR_EPOCH_OVERFLOW'

    def craft_ghost_i_am(self, device_id, hidden_network, fake_vmac_hex):
        """
        Generates a structurally complete BACnet/IP I-Am frame forwarded via 
        a virtual router. Fully compatible with BACteria TLV parser slicing.
        """
        # ---- 1. BVLL LAYER (BACnet/IP Virtual Link Layer) ----
        bvll_header = bytearray([0x81, 0x0b, 0x00, 0x00])
        
        # ---- 2. NPDU LAYER (Network Protocol Data Unit) ----
        npdu = bytearray()
        npdu.append(0x01)  # Protocol Version: 1
        npdu.append(0x08)  # Network Control Flag: Source Specifier present (triggers resp[5] == 0x08)
        
        # SNET: Source Network Number (2 Bytes)
        npdu.extend(int(hidden_network).to_bytes(2, byteorder='big'))
        
        # SLEN: Source MAC Address Length (6 bytes for virtualized IP/Port combo)
        vmac_bytes = bytes.fromhex(fake_vmac_hex)
        npdu.append(len(vmac_bytes))
        
        # SADR: Source hardware address (The Virtual MAC)
        npdu.extend(vmac_bytes)
        
        # Hop Count (Mandatory when routing flag 0x08 is set)
        npdu.append(0xff) 
        
        # ---- 3. APDU LAYER (Application Protocol Data Unit) ----
        apdu = bytearray()
        apdu.append(0x10)  # APDU Type: Unconfirmed-Request-PDU
        apdu.append(0x08)  # Service Choice: I-Am
        
        # Object Identifier TLV: Tag Number 12 (Object Identifier), Length 4
        apdu.append(0xc4)  
        
        # Combine Object Type (Device = 8) shifted into 22-bits with the target ID
        type_and_instance = (8 << 22) | int(device_id)
        apdu.extend(type_and_instance.to_bytes(4, byteorder='big'))
        
        # Max APDU Length Accepted TLV: Tag Number 2 (Unsigned Integer), Length 2
        apdu.extend([0x22, 0x05, 0xdc])  # 0x05DC = 1500 bytes
        
        # Segmentation Supported TLV: Tag Number 1 (Enumerated), Length 1
        apdu.extend([0x91, 0x00])        # 0x00 = No Segmentation
        
        # Vendor ID TLV: Tag Number 2 (Unsigned Integer), Length 1
        apdu.extend([0x21, 0x58])        # 0x58 = Vendor 88 (Metro-Transit Automation Corp)
        
        # ---- 4. PACKET ASSEMBLY & LENGTH MATRICES ----
        full_payload = npdu + apdu
        total_packet_length = len(bvll_header) + len(full_payload)
        
        # Update length fields inside BVLL header
        bvll_header[2] = (total_packet_length >> 8) & 0xff
        bvll_header[3] = total_packet_length & 0xff
        
        return bytes(bvll_header + full_payload)


def start_honeypot():
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    else:
        target_ip = '127.0.0.1'

    listen_address = f"{target_ip}/24:47808"
    
    logging.basicConfig(level=logging.ERROR)
    logging.getLogger("bacpypes").setLevel(logging.ERROR)

    # Transit Automation Device Metadata
    device_info = {
        'device_id': 40201,                            
        'object_name': 'SUBWAY_L4_PLAT2_TCB',       
        'model_name': 'AS-B 247',                       
        'vendor_id': 10,                                
        'vendor_name': 'Metro-Transit Automation Corp',               
        'location': 'Line 4 Central Interchange - Room 102B',          
        'firmware': 'Server 5.2.1002',                          
        'software': 'OS_Nexus_Transit_Pro',                           
        'description': 'Core Node - Platform Management, Ventilation and Emergency Interlock Controller' 
    }

    try:
        local_device = LocalDeviceObject(
            objectIdentifier=('device', device_info['device_id']),
            objectName=device_info['object_name'],
            vendorIdentifier=device_info['vendor_id'],
            vendorName=device_info['vendor_name'],
            modelName=device_info['model_name'],
            location=device_info['location'],          
            firmwareRevision=device_info['firmware'],
            applicationSoftwareVersion=device_info['software'],
            description=device_info['description']
        )

        bacnet_app = BACHoneypot(local_device, listen_address)
        normal_status = StatusFlags([0, 0, 0, 0]) 
        
        # Subway Station Platform 2 Asset List
        assets = [
            # Network Port
            NetworkPortObject(objectIdentifier=('networkPort', 1), objectName='TRANSIT_OT_RING_UPLINK', description='Primary Fiber Ring Connection to Station Switch', statusFlags=normal_status),
            
            # Analog Inputs (Environmental Sensors)
            AnalogInputObject(objectIdentifier=('analogInput', 0), objectName='AI_TUNNEL_TEMP', description='Tunnel Ambient Temperature C', presentValue=24.5, statusFlags=normal_status, outOfService=False),
            AnalogInputObject(objectIdentifier=('analogInput', 1), objectName='AI_PLATFORM_RH', description='Passenger Platform Relative Humidity %', presentValue=48.2, statusFlags=normal_status, outOfService=False),
            AnalogInputObject(objectIdentifier=('analogInput', 2), objectName='AI_AIR_QUALITY_PM', description='Brake Dust Particulate Matter Index', presentValue=12.0, statusFlags=normal_status, outOfService=False),
            AnalogInputObject(objectIdentifier=('analogInput', 3), objectName='AI_PISTON_AIRFLOW', description='Train Piston Effect Velocity m/s', presentValue=1.2, statusFlags=normal_status, outOfService=False),
            
            # Analog Outputs (Actuators)
            AnalogOutputObject(objectIdentifier=('analogOutput', 1), objectName='AO_VAV_DAMPER_POS', description='Fresh Air Intake Damper Modulation 0-10V', presentValue=65.0, statusFlags=normal_status, outOfService=False),
            
            # Analog Values (Calculated Control Loop Metrics)
            AnalogValueObject(objectIdentifier=('analogValue', 0), objectName='AV_THERMAL_COMFORT', description='Calculated Passenger PMV Index', presentValue=0.1, statusFlags=normal_status, outOfService=False),
            AnalogValueObject(objectIdentifier=('analogValue', 1), objectName='AV_TARGET_HZ_FAN1', description='Target Frequency VFD Exhaust Fan 1', presentValue=45.0, statusFlags=normal_status, outOfService=False),
            AnalogValueObject(objectIdentifier=('analogValue', 2), objectName='AV_TARGET_HZ_FAN2', description='Target Frequency VFD Exhaust Fan 2', presentValue=45.0, statusFlags=normal_status, outOfService=False),
            AnalogValueObject(objectIdentifier=('analogValue', 3), objectName='AV_FLOW_RATE_CFM', description='Calculated Volumetric Air Extraction', presentValue=12500.0, statusFlags=normal_status, outOfService=False),
            
            # Binary Inputs (Physical Interlocks)
            BinaryInputObject(objectIdentifier=('binaryInput', 0), objectName='BI_TRACK_ESTOP_PLUNGER', description='Trackway Emergency E-Stop Circuit Status', presentValue=0, statusFlags=normal_status, outOfService=False),
            BinaryInputObject(objectIdentifier=('binaryInput', 1), objectName='BI_SCREEN_DOORS_LOCKED', description='Platform Screen Doors Closed and Interlocked', presentValue=1, statusFlags=normal_status, outOfService=False),
            BinaryInputObject(objectIdentifier=('binaryInput', 2), objectName='BI_TECH_RM_VAULT_DOOR', description='Signal Tech Room Enclosure Tamper Switch', presentValue=0, statusFlags=normal_status, outOfService=False),
            BinaryInputObject(objectIdentifier=('binaryInput', 3), objectName='BI_SUMP_HIGH_FLOAT', description='Under-Platform Sump High Water Level Sensor', presentValue=0, statusFlags=normal_status, outOfService=False),
            BinaryInputObject(objectIdentifier=('binaryInput', 4), objectName='BI_VENT_AIRFLOW_PROV', description='Exhaust Plenum Sail Switch Flow Proven Status', presentValue=1, statusFlags=normal_status, outOfService=False),
            
            # Binary Output (Mechanical Relays)
            BinaryOutputObject(objectIdentifier=('binaryOutput', 1), objectName='BO_SUMP_PUMP_RELAY', description='Drainage Sump Motor Starter Relay Contact', presentValue=0, statusFlags=normal_status, outOfService=False),
            
            # Binary Values (Logic Interlocks & Mode Status)
            BinaryValueObject(objectIdentifier=('binaryValue', 0), objectName='BV_DISPATCH_LOCKOUT', description='Central OCC SCADA Remote Override Interlock', presentValue=0, statusFlags=normal_status, outOfService=False),
            BinaryValueObject(objectIdentifier=('binaryValue', 1), objectName='BV_COMMUTER_PEAK_FLAG', description='Time-of-Day Commuter Density Traffic Bit', presentValue=1, statusFlags=normal_status, outOfService=False),
            
            # Character String Value (SCADA Routing / API Token)
            CharacterStringValueObject(objectIdentifier=('characterstringValue', 0), objectName='STR_VAL_01', description='Central OCC Network Routing Mesh ID', presentValue='F0XGR1D', statusFlags=normal_status),
            
            # Commands (Emergency Macro Push Triggers)
            CommandObject(objectIdentifier=('command', 0), objectName='CMD_SMOKE_EVAC_PURGE', description='ACTIVATE TUNNEL REVERSE SMOKE EXTRACTION MACRO', presentValue=0, statusFlags=normal_status, inProcess=False),
            CommandObject(objectIdentifier=('command', 1), objectName='CMD_FLOOD_ISOLATION', description='ACTIVATE STATION VENT SHAFT DAMPER SHUTDOWN', presentValue=0, statusFlags=normal_status, inProcess=False),
            CommandObject(objectIdentifier=('command', 2), objectName='CMD_EVAC_SIREN_STRB', description='ACTIVATE PLATFORM AUDIBLE ALARM SYSTEM PUSH', presentValue=0, statusFlags=normal_status, inProcess=False),
            CommandObject(objectIdentifier=('command', 3), objectName='CMD_SYS_SELF_TEST', description='RUN DIAGNOSTIC STEP ON VFD AND FLOOD RELAYS', presentValue=0, statusFlags=normal_status, inProcess=False),
            
            # Integers & Notifications
            IntegerValueObject(objectIdentifier=('integerValue', 1), objectName='INT_ACTIVE_HVAC_RECIPE', description='Active Season Schedule Profile ID Code', presentValue=202, statusFlags=normal_status),
            NotificationClassObject(objectIdentifier=('notificationClass', 0), objectName='NC_CRITICAL_LIFE_SAFETY', description='OCC High Priority Alert Routing Dispatcher', notificationClass=0, priority=[1, 1, 1], ackRequired=[1, 1, 1]),
            NotificationClassObject(objectIdentifier=('notificationClass', 1), objectName='NC_GENERAL_MAINTENANCE', description='Depot Technical Team Advisory Alert Router', notificationClass=1, priority=[128, 128, 128], ackRequired=[0, 0, 0]),
            
            # Life Safety Elements
            LifeSafetyPointObject(objectIdentifier=('lifeSafetyPoint', 0), objectName='SAFE_ZONE_3RD_RAIL_PWR', description='Traction Power Third-Rail Energized Feedback', presentValue=1, statusFlags=normal_status),
            
            # Load Controls
            LoadControlObject(objectIdentifier=('loadControl', 0), objectName='LOAD_SHED_MUNI_GRID', description='Municipal Smart-Grid Peak Load Shed Shed Interlock', presentValue=0, statusFlags=normal_status),
            
            # Multi-State Inputs
            MultiStateInputObject(objectIdentifier=('multiStateInput', 0), objectName='MSI_STATION_MODE', description='Platform System Overall Status Vector Index', presentValue=1, numberOfStates=4, statusFlags=normal_status),
            
            # Multi-State Output
            MultiStateOutputObject(objectIdentifier=('multiStateOutput', 1), objectName='MSO_SIGNAGE_DISP', description='Platform LED Passenger Information Board Template ID', presentValue=1, numberOfStates=8, statusFlags=normal_status),
            
            # Lighting Outputs (Platform Illumination Sub-circuits)
            LightingOutputObject(objectIdentifier=('lightingOutput', 1), objectName='LGT_BANK_PLAT_WEST', description='Passenger Waiting Zone West Side LED Circuit', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 2), objectName='LGT_BANK_PLAT_EAST', description='Passenger Waiting Zone East Side LED Circuit', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 3), objectName='LGT_BANK_TRACK_EDGE1', description='Platform Edge Tactile Strip Warning Illumination 1', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 4), objectName='LGT_BANK_TRACK_EDGE2', description='Platform Edge Tactile Strip Warning Illumination 2', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 5), objectName='LGT_BANK_TUNNEL_HEAD', description='Tunnel Approach Bore Operations Illumination Block', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 6), objectName='LGT_BANK_TUNNEL_TAIL', description='Tunnel Departure Bore Operations Illumination Block', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 7), objectName='LGT_BANK_EGRESS_WAY1', description='Emergency Escape Shaft Directional Wayfinding Matrix 1', statusFlags=normal_status),
            LightingOutputObject(objectIdentifier=('lightingOutput', 8), objectName='LGT_BANK_EGRESS_WAY2', description='Emergency Escape Shaft Directional Wayfinding Matrix 2', statusFlags=normal_status),
            
            # Octet Strings (Cryptographic Hex Identifiers)
            OctetStringValueObject(objectIdentifier=('octetstringValue', 0), objectName='HEX_CRYPTO_NODE_SIGN', description='Hardware Root-of-Trust Secure Boot Hash Key', presentValue=b'\xAB\xCD\x12\x34', statusFlags=normal_status),
            
            # Positive Integers
            PositiveIntegerValueObject(objectIdentifier=('positiveIntegerValue', 0), objectName='UINT_TRAIN_COUNT_DAILY', description='Total Inbound Trains Logged Since Midnight', presentValue=142, statusFlags=normal_status),
            
            # Schedules (Time tables)
            ScheduleObject(objectIdentifier=('schedule', 0), objectName='SCHED_PEAK_SERVICE', description='Commuter Train Peak Timetable Calendar Matcher', statusFlags=normal_status),
            ScheduleObject(objectIdentifier=('schedule', 1), objectName='SCHED_NIGHT_MAINT', description='Maintenance Window Power Optimization Timeline Tracker', statusFlags=normal_status),
            ScheduleObject(objectIdentifier=('schedule', 2), objectName='SCHED_HVAC_COMFORT', description='Standard Station Ventilation Operation Timetable Block', statusFlags=normal_status),
            ScheduleObject(objectIdentifier=('schedule', 3), objectName='SCHED_LIGHTING_AUTO', description='Station Passenger Lighting Brightness Timetable Block', statusFlags=normal_status),
            
            # Accumulators
            AccumulatorObject(objectIdentifier=('accumulator', 0), objectName='TOTALIZER_TURNSTILE_IN', description='Cumulative Passenger Turnstile Ingress Pulse Counter', presentValue=24502, statusFlags=normal_status, scale=1, maxPresValue=9999999),
        ]

        for asset in assets:
            bacnet_app.add_object(asset)

        print(f"[*] BACnet activated and hosting on {listen_address}")
        run()

    except Exception as e:
        print(f"[-] Operational runtime failure: {e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        start_honeypot()
    except (KeyboardInterrupt, SystemExit):
        stop()
        print("\n[-] Honeypot successfully shutdown.")
