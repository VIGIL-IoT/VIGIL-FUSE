module permissive_tie (
  output logic security_bypass,
  output logic debug_disable
);
  assign security_bypass = 1'b1;
  assign debug_disable = 1'b0;
endmodule
