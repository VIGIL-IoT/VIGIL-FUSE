from __future__ import annotations

import re
from pathlib import Path

from .model import HardwareArtifact


_FORMATS: dict[str, tuple[str, str]] = {
    ".kicad_sch": ("schematic", "KiCad schematic"),
    ".schdoc": ("schematic", "Altium schematic"),
    ".sch": ("schematic", "Eagle or legacy schematic"),
    ".kicad_pcb": ("pcb-layout", "KiCad PCB layout"),
    ".pcbdoc": ("pcb-layout", "Altium PCB layout"),
    ".brd": ("pcb-layout", "Eagle PCB layout"),
    ".pcb": ("pcb-layout", "PCB layout"),
    ".prjpcb": ("hardware-project", "Altium PCB project"),
    ".schlib": ("hardware-library", "Altium schematic library"),
    ".pcblib": ("hardware-library", "Altium PCB library"),
    ".kicad_pro": ("hardware-project", "KiCad project"),
    ".kicad_sym": ("hardware-library", "KiCad symbol library"),
    ".kicad_mod": ("hardware-library", "KiCad footprint"),
    ".kicad_wks": ("hardware-project", "KiCad worksheet"),
    ".kicad_dru": ("hardware-project", "KiCad design rules"),
    ".lbr": ("hardware-library", "Eagle library"),
    ".fzz": ("hardware-project", "Fritzing project"),
    ".fzb": ("hardware-library", "Fritzing parts bin"),
    ".fzp": ("hardware-library", "Fritzing part definition"),
    ".fz": ("hardware-project", "Fritzing project"),
    ".gbrjob": ("fabrication", "Gerber job"),
    ".gerber": ("fabrication", "Gerber layer"),
    ".gbr": ("fabrication", "Gerber layer"),
    ".ger": ("fabrication", "Gerber layer"),
    ".drl": ("fabrication", "Excellon drill file"),
    ".xln": ("fabrication", "Excellon drill file"),
    ".gko": ("fabrication", "Gerber board outline"),
    ".gtl": ("fabrication", "Gerber top copper"),
    ".gbl": ("fabrication", "Gerber bottom copper"),
    ".gts": ("fabrication", "Gerber top solder mask"),
    ".gbs": ("fabrication", "Gerber bottom solder mask"),
    ".gto": ("fabrication", "Gerber top silkscreen"),
    ".gbo": ("fabrication", "Gerber bottom silkscreen"),
    ".gml": ("fabrication", "Gerber mechanical layer"),
    ".gm1": ("fabrication", "Gerber mechanical layer"),
    ".net": ("netlist", "Electronic netlist"),
    ".step": ("mechanical-cad", "STEP model"),
    ".stp": ("mechanical-cad", "STEP model"),
    ".iges": ("mechanical-cad", "IGES model"),
    ".igs": ("mechanical-cad", "IGES model"),
    ".stl": ("mechanical-cad", "STL model"),
    ".3mf": ("mechanical-cad", "3MF model"),
    ".fcstd": ("mechanical-cad", "FreeCAD document"),
    ".v": ("hdl", "Verilog source"),
    ".sv": ("hdl", "SystemVerilog source"),
    ".vhd": ("hdl", "VHDL source"),
    ".vhdl": ("hdl", "VHDL source"),
    ".xdc": ("hdl", "FPGA constraints"),
    ".pcf": ("hdl", "FPGA pin constraints"),
    ".qsf": ("hdl", "Quartus settings"),
    ".sdc": ("hdl", "Timing constraints"),
    ".xpr": ("hdl", "Vivado project"),
    ".qpf": ("hdl", "Quartus project"),
    ".hwh": ("hdl", "FPGA hardware handoff"),
    ".bd": ("hdl", "Vivado block design"),
    ".edf": ("hdl", "Electronic design interchange"),
    ".edif": ("hdl", "Electronic design interchange"),
}
_BOM_EXTENSIONS = {".csv", ".tsv", ".xlsx", ".xls", ".ods", ".json", ".xml", ".bom"}


def classify_hardware_file(path: Path, display_path: str) -> HardwareArtifact | None:
    """Classify known hardware formats by filename without opening their contents."""
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    if suffix == ".net" and name.startswith("kconfig."):
        return None
    if suffix in _BOM_EXTENSIONS:
        tokens = set(re.split(r"[^a-z0-9]+", path.stem.casefold()))
        compact_name = re.sub(r"[^a-z0-9]+", "", path.stem.casefold())
        is_bom = (
            "bom" in tokens
            or {"bill", "of", "materials"}.issubset(tokens)
            or "billofmaterials" in compact_name
            or "partslist" in compact_name
        )
        if is_bom:
            return HardwareArtifact(display_path, "bill-of-materials", f"BOM {suffix.lstrip('.').upper()}")
    recognized = _FORMATS.get(suffix)
    if recognized is None:
        # Multi-part KiCad extensions are checked explicitly because Path.suffix
        # only returns the final component.
        for ending in (".kicad_sch", ".kicad_pcb", ".kicad_pro", ".gbrjob"):
            if name.endswith(ending):
                recognized = _FORMATS[ending]
                break
    if recognized is None:
        return None
    category, format_name = recognized
    return HardwareArtifact(display_path, category, format_name)
