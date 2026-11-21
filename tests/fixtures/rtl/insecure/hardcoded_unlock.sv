module hardcoded_unlock (
  input logic unlock_request,
  input logic [31:0] unlock_code,
  output logic auth_ok
);
  assign auth_ok = unlock_request && (unlock_code == 32'hC0DECAFE);
endmodule
