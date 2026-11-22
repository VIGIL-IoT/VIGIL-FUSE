`include "security_defaults.svh"

module secure_access #(
  parameter logic [31:0] RESET_VALUE = `SECURITY_LOCKED
) (
  input logic clk,
  input logic rst_n,
  input logic [31:0] presented_key,
  input logic [31:0] enrolled_key,
  output logic auth_ok,
  output logic debug_enable
);
  logic debug_mux;

  assign debug_enable = 1'b0;
  assign debug_mux = debug_enable ? presented_key[0] : enrolled_key[0];

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      auth_ok <= 1'b0;
    end else begin
      auth_ok <= (presented_key == enrolled_key);
    end
  end
endmodule

module reset_branch_boundary (
  input logic clk,
  input logic rst_n,
  output logic security_state
);
  always_ff @(posedge clk or negedge rst_n) begin
    if (rst_n) begin
      security_state <= 1'b1;
    end else begin
      security_state <= 1'b0;
    end
  end
endmodule
