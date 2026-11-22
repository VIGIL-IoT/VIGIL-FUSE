from vigil_fuse.device_tree import MAX_DTS_BYTES, MAX_DTS_DEPTH, parse_device_tree


def test_literal_nodes_and_properties_are_preserved_without_preprocessing() -> None:
    result = parse_device_tree(b"""/dts-v1/;
        #include "board.dtsi"
        / { aliases { serial0 = &uart2; };
            soc { uart2: serial@40004400 {
                compatible = "vendor,uart"; status = "okay";
                reg = <0x40004400 0x400>; interrupts = <38>;
                pinctrl-0 = <&uart2_pins>;
            }; };
        };""")
    assert result.status == "partial"
    nodes = {node.path: node for node in result.nodes}
    uart = nodes["/soc/serial@40004400"]
    assert uart.label == "uart2"
    assert uart.property("reg") == "<0x40004400 0x400>"
    assert uart.property("pinctrl-0") == "<&uart2_pins>"
    assert nodes["/aliases"].property("serial0") == "&uart2"


def test_invalid_and_unsupported_are_never_complete() -> None:
    assert parse_device_tree(b'/ { a { status = "okay"; };').status == "invalid"
    assert parse_device_tree(b"/ { /* incomplete").status == "invalid"
    assert parse_device_tree(b'&uart2 { status = "okay"; };').status == "partial"
    assert parse_device_tree(b"x" * (MAX_DTS_BYTES + 1)).status == "invalid"


def test_quoted_delimiters_and_comments() -> None:
    result = parse_device_tree(b'/ { x { compatible = "test;{x}"; /* } */ }; };')
    assert result.status == "parsed"
    assert result.nodes[-1].property("compatible") == '"test;{x}"'


def test_depth_limit_is_enforced() -> None:
    text = b"/ {" + b"x {" * MAX_DTS_DEPTH + b"};" * (MAX_DTS_DEPTH + 1)
    result = parse_device_tree(text)
    assert result.status == "invalid"
    assert "limit" in result.limitations[0]
