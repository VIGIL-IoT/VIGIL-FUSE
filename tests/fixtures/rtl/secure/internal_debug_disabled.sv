module internal_debug_disabled (
  input logic secret_data,
  output logic debug_enable,
  output logic debug_path
);
  assign debug_enable = 1'b0;
  assign debug_path = debug_enable ? secret_data : 1'b0;
endmodule
