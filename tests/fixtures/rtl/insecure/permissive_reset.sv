module permissive_reset (
  input logic clk,
  input logic rst_n,
  output logic debug_enable
);
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      debug_enable <= 1'b1;
    end else begin
      debug_enable <= 1'b0;
    end
  end
endmodule
