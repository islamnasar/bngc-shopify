import express from "express";
import crypto from "crypto";

const app = express();
app.use("/webhooks", express.raw({ type: "application/json" }));

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";

function verifyShopifyWebhook(req) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || "";
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(req.body)
    .digest("base64");

  const a = Buffer.from(digest);
  const b = Buffer.from(hmacHeader);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.get("/", (req, res) => res.send("BNGC server is running"));

app.post("/webhooks/orders_paid", (req, res) => {
  if (!SHOPIFY_WEBHOOK_SECRET) {
    return res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");
  }

  const ok = verifyShopifyWebhook(req);
  if (!ok) return res.status(401).send("Invalid webhook signature");

  console.log("orders/paid webhook received (VERIFIED)");
  return res.status(200).send("OK");
});

app.listen(process.env.PORT || 3000, () => console.log("Server started"));
