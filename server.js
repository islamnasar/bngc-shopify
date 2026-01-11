import express from "express";

const app = express();
app.use("/webhooks", express.raw({ type: "application/json" }));

app.get("/", (req, res) => {
  res.send("BNGC server is running");
});

app.post("/webhooks/orders_paid", (req, res) => {
  console.log("orders/paid webhook received (TEST MODE)");
  return res.status(200).send("OK");
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server started");
});
