module macro_debug (
  input logic request,
  output logic debug_enable
);
`ifdef FUSE_ENABLE_DEBUG
  assign debug_enable = 1'b1;
`else
  assign debug_enable = 1'b0;
`endif
endmodule
