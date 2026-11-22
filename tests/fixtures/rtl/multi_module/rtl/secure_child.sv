module secure_child (
  input logic clk,
  input logic rst_n,
  input logic request,
  output logic result
);
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      result <= 1'b0;
    end else begin
      result <= request;
    end
  end
endmodule
