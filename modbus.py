from pymodbus.client import ModbusTcpClient
import time

def modbus_read_coils(host, port, address, count):
    """Reads coils from a Modbus TCP device."""
    client = ModbusTcpClient(host, port)
    if not client.connect():
        print(f"Failed to connect to Modbus device at {host}:{port}")
        return None

    try:
        response = client.read_coils(address, count)
        if not response.isError():
            print(f"Read Coils from address {address}: {response.bits}")
            return response.bits
        else:
            print(f"Modbus Error: {response}")
            return None
    except Exception as e:
        print(f"An error occurred during Modbus read: {e}")
        return None
    finally:
        client.close()

def modbus_write_coil(host, port, address, value):
    """Writes a single coil to a Modbus TCP device."""
    client = ModbusTcpClient(host, port)
    if not client.connect():
        print(f"Failed to connect to Modbus device at {host}:{port}")
        return False

    try:
        response = client.write_coil(address, value)
        if not response.isError():
            print(f"Successfully wrote coil {address} = {value}")
            return True
        else:
            print(f"Modbus Error: {response}")
            return False
    except Exception as e:
        print(f"An error occurred during Modbus write: {e}")
        return False
    finally:
        client.close()

if __name__ == "__main__":
    # Example usage: You'd need a Modbus TCP server running
    # You can set one up with `pymodbus.server.sync` (see pymodbus docs)
    print("--- Modbus Interaction Template ---")
    # modbus_read_coils("127.0.0.1", 502, 0, 8)
    # modbus_write_coil("127.0.0.1", 502, 0, True)