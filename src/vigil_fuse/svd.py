"""Bounded CMSIS-SVD literal register inventory; never resolves external entities."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import xml.etree.ElementTree as ET
from xml.parsers import expat

MAX_SVD_BYTES = 10 * 1024 * 1024
MAX_SVD_ELEMENTS = 100_000
MAX_SVD_DEPTH = 128
MAX_SVD_PERIPHERALS = 2048
MAX_SVD_REGISTERS = 10_000
MAX_SVD_FIELDS = 50_000
MAX_SVD_TEXT_CHARS = 1024


@dataclass(frozen=True)
class EnumeratedValue:
    name: str
    value: int | None
    usage: str | None


@dataclass(frozen=True)
class FieldModel:
    name: str
    bit_offset: int | None
    bit_width: int | None
    access: str | None
    enumerated_values: tuple[EnumeratedValue, ...]


@dataclass(frozen=True)
class RegisterModel:
    name: str
    offset: int
    size_bits: int | None
    access: str | None
    reset_value: int | None
    reset_mask: int | None
    fields: tuple[FieldModel, ...]


@dataclass(frozen=True)
class PeripheralModel:
    name: str
    base_address: int
    interrupts: tuple[tuple[str, int], ...]
    registers: tuple[RegisterModel, ...]


@dataclass(frozen=True)
class DeviceModel:
    name: str
    version: str | None
    source: str
    sha256: str
    peripherals: tuple[PeripheralModel, ...]


@dataclass(frozen=True)
class SvdResult:
    status: str
    device: DeviceModel | None = None
    limitations: tuple[str, ...] = ()


def _preflight(data: bytes) -> None:
    data.decode("utf-8-sig")
    parser = expat.ParserCreate()
    depth = 0
    count = 0

    def start(_name: str, _attributes: dict[str, str]) -> None:
        nonlocal depth, count
        depth += 1
        count += 1
        if depth > MAX_SVD_DEPTH or count > MAX_SVD_ELEMENTS:
            raise ValueError("SVD XML structure limit exceeded")

    def end(_name: str) -> None:
        nonlocal depth
        depth -= 1

    def reject(*_args: object) -> None:
        raise ValueError("SVD DTD and entity declarations are not accepted")

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = lambda *_args: 0
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(data, True)


def _text(element: ET.Element, tag: str) -> str | None:
    value = element.findtext(tag)
    if value and len(value) > MAX_SVD_TEXT_CHARS:
        raise ValueError("SVD text field limit exceeded")
    return value.strip() if value and value.strip() else None


def _number(value: str | None) -> int | None:
    if value is None:
        return None
    if len(value) > 256:
        raise ValueError("SVD numeric value exceeds the digit limit")
    if re.fullmatch(r"[0-9]+", value):
        return int(value, 10)
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        return int(value, 16)
    if re.fullmatch(r"#(?:0|1)+", value):
        return int(value[1:], 2)
    raise ValueError("Unsupported SVD numeric value")


def _required_number(element: ET.Element, tag: str) -> int:
    value = _number(_text(element, tag))
    if value is None:
        raise ValueError(f"Missing SVD {tag}")
    return value


def _required_name(element: ET.Element) -> str:
    value = _text(element, "name")
    if value is None:
        raise ValueError("Missing SVD name")
    return value


def parse_svd(data: bytes, source: str) -> SvdResult:
    """Parse a single local description. Unsupported constructs remain partial."""
    if len(data) > MAX_SVD_BYTES:
        return SvdResult("invalid", limitations=("SVD byte limit exceeded",))
    if not source or len(source) > MAX_SVD_TEXT_CHARS:
        return SvdResult("invalid", limitations=("SVD source label is missing or too long",))
    try:
        _preflight(data)
        document = ET.fromstring(data)
        if document.tag != "device":
            raise ValueError("SVD root must be device")
        name = _required_name(document)
        container = document.find("peripherals")
        if container is None:
            raise ValueError("SVD peripherals are missing")
        peripheral_elements = container.findall("peripheral")
        if len(peripheral_elements) > MAX_SVD_PERIPHERALS:
            raise ValueError("SVD peripheral limit exceeded")
        limitations = {
            "SVD metadata is unverified and does not establish hardware or runtime behavior."
        }
        peripheral_names: set[str] = set()
        peripherals: list[PeripheralModel] = []
        register_count = 0
        field_count = 0
        for peripheral in peripheral_elements:
            peripheral_name = _required_name(peripheral)
            if peripheral_name in peripheral_names:
                raise ValueError("Duplicate SVD peripheral name")
            peripheral_names.add(peripheral_name)
            if peripheral.get("derivedFrom") or peripheral.find("dim") is not None:
                limitations.add("Derived or array peripherals were omitted.")
                continue
            base = _required_number(peripheral, "baseAddress")
            default_access = _text(peripheral, "access") or _text(document, "access")
            default_size = _text(peripheral, "size") or _text(document, "size")
            default_reset = _text(peripheral, "resetValue") or _text(document, "resetValue")
            default_mask = _text(peripheral, "resetMask") or _text(document, "resetMask")
            interrupts = tuple(
                sorted(
                    (_required_name(item), _required_number(item, "value"))
                    for item in peripheral.findall("interrupt")
                )
            )
            registers_element = peripheral.find("registers")
            if registers_element is None:
                limitations.add("At least one peripheral has no register section.")
                registers_elements: list[ET.Element] = []
            else:
                if registers_element.find("cluster") is not None:
                    limitations.add("Register clusters were omitted.")
                registers_elements = registers_element.findall("register")
            registers: list[RegisterModel] = []
            register_names: set[str] = set()
            for register in registers_elements:
                register_count += 1
                if register_count > MAX_SVD_REGISTERS:
                    raise ValueError("SVD register limit exceeded")
                register_name = _required_name(register)
                if register_name in register_names:
                    raise ValueError("Duplicate SVD register name")
                register_names.add(register_name)
                if register.get("derivedFrom") or register.find("dim") is not None:
                    limitations.add("Derived or array registers were omitted.")
                    continue
                access = _text(register, "access") or default_access
                reset = _number(_text(register, "resetValue") or default_reset)
                mask = _number(_text(register, "resetMask") or default_mask)
                fields: list[FieldModel] = []
                field_names: set[str] = set()
                for field in register.findall("./fields/field"):
                    field_count += 1
                    if field_count > MAX_SVD_FIELDS:
                        raise ValueError("SVD field limit exceeded")
                    field_name = _required_name(field)
                    if field_name in field_names:
                        raise ValueError("Duplicate SVD field name")
                    field_names.add(field_name)
                    if field.get("derivedFrom") or field.find("dim") is not None:
                        limitations.add("Derived or array fields were omitted.")
                        continue
                    bit_offset = _number(_text(field, "bitOffset"))
                    bit_width = _number(_text(field, "bitWidth"))
                    if bit_offset is None or bit_width is None:
                        lsb, msb = _number(_text(field, "lsb")), _number(_text(field, "msb"))
                        if lsb is not None and msb is not None and msb >= lsb:
                            bit_offset, bit_width = lsb, msb - lsb + 1
                        else:
                            limitations.add("Some field bit ranges were not resolved.")
                    if bit_width == 0:
                        raise ValueError("SVD field width must be positive")
                    values: list[EnumeratedValue] = []
                    for group in field.findall("enumeratedValues"):
                        if group.get("derivedFrom"):
                            limitations.add("Derived enumerated values were omitted.")
                            continue
                        for item in group.findall("enumeratedValue"):
                            values.append(
                                EnumeratedValue(
                                    _required_name(item),
                                    _number(_text(item, "value")),
                                    _text(group, "usage"),
                                )
                            )
                    fields.append(
                        FieldModel(
                            field_name,
                            bit_offset,
                            bit_width,
                            _text(field, "access") or access,
                            tuple(values),
                        )
                    )
                size_bits = _number(_text(register, "size") or default_size)
                if size_bits == 0:
                    raise ValueError("SVD register size must be positive")
                registers.append(
                    RegisterModel(
                        register_name,
                        _required_number(register, "addressOffset"),
                        size_bits,
                        access,
                        reset,
                        mask,
                        tuple(fields),
                    )
                )
            peripherals.append(PeripheralModel(peripheral_name, base, interrupts, tuple(registers)))
        device = DeviceModel(
            name,
            _text(document, "version"),
            source,
            hashlib.sha256(data).hexdigest(),
            tuple(peripherals),
        )
        # shortcut: not all SVD constructs are interpreted, upgrade before complete models.
        limitations.add("SVD schema and all vendor-specific semantics are not fully validated.")
        return SvdResult("partial", device, tuple(sorted(limitations)))
    except (ValueError, UnicodeError, expat.ExpatError, ET.ParseError, RecursionError) as error:
        return SvdResult("invalid", limitations=(str(error),))
