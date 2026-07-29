"""Shared safe Modbus helpers for the Sandworm lab emulation."""

import ipaddress
import json
import logging
from pathlib import Path

from pymodbus.client import ModbusTcpClient


def load_config(config_path: str | Path) -> dict:
    """Load and validate the shared lab configuration."""
    path = Path(config_path)

    if not path.is_file():
        raise FileNotFoundError(f"Configuration not found: {path}")

    with path.open(encoding="utf-8") as file:
        config = json.load(file)

    conpot_ip = config["hosts"]["conpot"]["ip"]
    allowed_coils = config["modbus"]["allowed_coils"]

    # Refuse unfinished placeholder values.
    if "REPLACE_WITH" in conpot_ip:
        raise ValueError("Replace the Conpot IP in lab.json before running.")

    if not allowed_coils or any(
        "REPLACE_WITH" in str(address) for address in allowed_coils
    ):
        raise ValueError("Configure approved Modbus register addresses first.")

    ipaddress.ip_address(conpot_ip)
    return config


def configure_logging(log_path: str | Path) -> logging.Logger:
    """Create an attacker-side action log."""
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    return logging.getLogger("modbus_lab")


class SafeModbusClient:
    """Conpot-only Modbus TCP client with register allowlisting."""

    def __init__(self, config: dict, logger: logging.Logger):
        self.config = config
        self.logger = logger

        conpot = config["hosts"]["conpot"]
        modbus = config["modbus"]

        self.host = conpot["ip"]
        self.port = conpot["modbus_port"]
        self.unit_id = modbus["unit_id"]
        self.timeout = modbus["timeout_seconds"]

        self.allowed_coils = sorted({
            int(address) for address in modbus["allowed_coils"]
        })
        self.allowed_write_values = {
            int(address): bool(value)
            for address, value in modbus["write_values"].items()
        }

        self.client = ModbusTcpClient(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )

    def connect(self) -> None:
        """Connect only to the configured Conpot server."""
        if not self.client.connect():
            raise ConnectionError(
                f"Could not connect to configured Conpot target: "
                f"{self.host}:{self.port}"
            )

        self.logger.info(
            "CONNECTED | destination=%s:%s | unit_id=%s",
            self.host,
            self.port,
            self.unit_id,
        )

    def _require_allowed_coil(self, address: int) -> None:
        if address not in self.allowed_coils:
            raise ValueError(f"Register {address} is not allowlisted.")

    def read_coil(self, address: int) -> int:
        """Read one approved holding register."""
        self._require_allowed_coil(address)

        response = self.client.read_coils(
            address=address,
            count=1,
            device_id=self.unit_id,
        )

        if response.isError():
            raise RuntimeError(f"Modbus read failed: {response}")

        value = response.bits[0]
        self.logger.info(
            "READ | address=%s | value=%s | destination=%s",
            address,
            value,
            self.host,
        )
        return value

    def write_coil(self, address: int, value: int) -> None:
        """Write only the configured safe value to an approved register."""
        self._require_allowed_coil(address)

        expected_value = self.allowed_write_values.get(address)
        if expected_value != value:
            raise ValueError(
                f"Refusing write: {address} may only receive "
                f"configured value {expected_value}."
            )

        response = self.client.write_coil(
            address=address,
            value=value,
            device_id=self.unit_id,
        )

        if response.isError():
            raise RuntimeError(f"Modbus write failed: {response}")

        self.logger.info(
            "WRITE | address=%s | value=%s | destination=%s",
            address,
            value,
            self.host,
        )

    def close(self) -> None:
        """Close the TCP session."""
        self.client.close()
        self.logger.info("DISCONNECTED | destination=%s:%s", self.host, self.port)

    def restore_coil(self, address: int, value: bool) -> None:
        """
    	Restore one allowlisted coil to its Boolean value from a validated baseline.

    	Unlike the attack-write method, this accepts either True or False because
    	the original baseline value may be false.
    	"""
        self._require_allowed_coil(address)

        if type(value) is not bool:
            raise ValueError("Restoration value must be True or False.")

        response = self.client.write_coil(
            address=address,
            value=value,
            device_id=self.unit_id,
        )

        if response.isError():
            raise RuntimeError(f"Modbus coil restoration failed: {response}")

        self.logger.info(
            "RESTORE | address=%s | value=%s | destination=%s",
            address,
            value,
            self.host,
        )