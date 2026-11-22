module external_debug_enable (
  input wire external_debug_enable,
  input wire protected_data,
  output wire debug_mux
);
  assign debug_mux = external_debug_enable ? protected_data : 1'b0;
endmodule
