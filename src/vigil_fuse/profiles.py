from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

BASE_SUFFIXES = frozenset(
    {
        ".c",
        ".h",
        ".cc",
        ".hh",
        ".cpp",
        ".hpp",
        ".ino",
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".swift",
        ".m",
        ".mm",
        ".php",
        ".rb",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".config",
        ".properties",
        ".xml",
        ".env",
        ".pem",
        ".gradle",
        ".mk",
        ".cmake",
        ".be",
        ".v",
        ".vh",
        ".sv",
        ".svh",
        ".ys",
    }
)
BASE_NAMES = frozenset({"dockerfile", "makefile", "platformio.ini", "idf_component.yml"})


@dataclass(frozen=True)
class ScanProfile:
    name: str
    description: str
    additional_suffixes: frozenset[str] = frozenset()
    additional_names: frozenset[str] = frozenset()
    include_base: bool = True

    def supports(self, path: Path) -> bool:
        name = path.name.lower()
        suffixes = self.additional_suffixes | (BASE_SUFFIXES if self.include_base else frozenset())
        names = self.additional_names | (BASE_NAMES if self.include_base else frozenset())
        return (
            path.suffix.lower() in suffixes
            or (self.include_base and (name == ".env" or name.startswith(".env.")))
            or name in names
            or (self.name == "esp-idf" and name.startswith("sdkconfig.defaults."))
        )


PROFILES: dict[str, ScanProfile] = {
    "generic": ScanProfile(
        name="generic",
        description="Common source code and configuration files.",
    ),
    "esp-idf": ScanProfile(
        name="esp-idf",
        description="ESP-IDF projects, including SDK configuration and partition tables.",
        additional_suffixes=frozenset({".csv", ".dts", ".dtsi"}),
        additional_names=frozenset(
            {
                "sdkconfig",
                "sdkconfig.defaults",
                "sdkconfig.ci",
                "kconfig.projbuild",
                "cmakelists.txt",
                "partitions.csv",
            }
        ),
    ),
    "zephyr": ScanProfile(
        name="zephyr",
        description="Zephyr projects, including Kconfig, board overlays, and prj.conf.",
        additional_suffixes=frozenset({".overlay", ".dts", ".dtsi", ".conf"}),
        additional_names=frozenset({"prj.conf", "kconfig", "west.yml", "cmakelists.txt"}),
    ),
    "embedded-linux": ScanProfile(
        name="embedded-linux",
        description="Embedded Linux projects, services, init scripts, and build recipes.",
        additional_suffixes=frozenset(
            {
                ".service",
                ".socket",
                ".network",
                ".target",
                ".bb",
                ".bbappend",
                ".dts",
                ".dtsi",
                ".init",
                ".rules",
            }
        ),
        additional_names=frozenset({"inittab", "rcs", "fstab", "cmakelists.txt"}),
    ),
    "rtl": ScanProfile(
        name="rtl",
        description="Verilog/SystemVerilog sources, Yosys scripts, and FPGA constraints.",
        additional_suffixes=frozenset(
            {".v", ".vh", ".sv", ".svh", ".ys", ".xdc", ".sdc", ".qsf", ".qpf", ".pcf", ".lpf", ".xpr"}
        ),
        include_base=False,
    ),
}


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name]
    except KeyError as error:
        choices = ", ".join(PROFILES)
        raise ValueError(f"Unknown profile '{name}'. Choose one of: {choices}") from error
