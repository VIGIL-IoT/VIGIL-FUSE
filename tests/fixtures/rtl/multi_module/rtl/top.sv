module fpga_top (
  input logic clk,
  input logic rst_n,
  input logic request,
  output logic result
);
  secure_child u_child (
    .clk(clk),
    .rst_n(rst_n),
    .request(request),
    .result(result)
  );
endmodule
