import asyncio
from datetime import datetime
from asyncua import Server, ua

async def main():
    server = Server()
    await server.init()

    # 1. SERVER ENDPOINT URL
    server.set_endpoint("opc.tcp://0.0.0.0:4840/Siemens/S7-1500/ProductionLine1/")

    # 2. APPLICATION & PRODUCT URIs (Overrides default urn:freeopcua:...)
    await server.set_application_uri("urn:SIMATIC.S7-1500.OPCUA.Server:ChemPlant:CPU1518")
    server.product_uri = "urn:Simatic:s7-1500"

    # 3. DISPLAY / SERVER NAME
    server.set_server_name("Siemens SIMATIC S7-1500 (CPU 1518-4 PN/DP - FW v2.9)")

    # 4. EXTENDED BUILD INFO (Server object properties: ns=0;i=2253)
    await server.set_build_info(
        product_uri="urn:Simatic:s7-1500",
        manufacturer_name="Siemens AG",
        product_name="SIMATIC S7-1500 CPU 1518-4 PN/DP",
        software_version="V2.9.2",
        build_number="2023.0412.14",
        build_date=datetime(2023, 4, 12, 14, 0, 0)
    )

    # 5. REGISTER VENDOR NAMESPACES
    idx_siemens = await server.register_namespace("https://www.siemens.com/s7-1500")
    idx_plant = await server.register_namespace("urn:ChemPlant:area03")

    # 6. BUILD INDUSTRIAL NODE TREE (ISA-95 Model)
    objects = server.nodes.objects
    
    # Area / Unit Hierarchy
    area_folder = await objects.add_folder(idx_plant, "Area_03_Filtration")
    unit_folder = await area_folder.add_folder(idx_plant, "Unit_31_CoagulantDosing")

    # Siemens S7 Data Block (DB101)
    db101 = await unit_folder.add_folder(idx_siemens, "DB101_Pump01_Control")

    # Process Variables with Explicit Siemens String NodeIDs
    temp_tag = await db101.add_variable(
        ua.NodeId('DB101_Pump01_Control.rCore_Temperature_Celsius', idx_siemens),
        "rCore_Temperature_Celsius",
        185.4
    )
    pressure_tag = await db101.add_variable(
        ua.NodeId('DB101_Pump01_Control.rReactor_Pressure_PSI', idx_siemens),
        "rReactor_Pressure_PSI",
        1200.0
    )
    e_stop_tag = await db101.add_variable(
        ua.NodeId('DB101_Pump01_Control.xEmergency_Shutdown_Tripped', idx_siemens),
        "xEmergency_Shutdown_Tripped",
        False
    )

    # Set Write Permissions for Metasploit Discovery
    await temp_tag.set_writable()
    await pressure_tag.set_writable()
    await e_stop_tag.set_writable()

    async with server:
        while True:
            await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())
