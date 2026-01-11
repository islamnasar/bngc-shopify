import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import nodemailer from "nodemailer";

const app = express();
app.use("/webhooks", express.raw({ type: "application/json" }));

const {
  // Shopify
  SHOPIFY_WEBHOOK_SECRET = "",
  SHOPIFY_SHOP_DOMAIN = "",     // مثال: yourstore.myshopify.com
  SHOPIFY_ADMIN_TOKEN = "",     // Admin API access token

  // Binance
  BINANCE_API_KEY = "",
  BINANCE_API_SECRET = "",

  // Zoho SMTP
  SMTP_HOST = "smtp.zoho.com",
  SMTP_PORT = "587",
  SMTP_SECURE = "false",        // false لـ 587, true لـ 465
  SMTP_USER = "",
  SMTP_PASS = "",
  SENDER_EMAIL = "",

  // Mode
  TEST_MODE = "true"            // خليها true في الأول
} = process.env;

/* ---------------- Shopify HMAC verify ---------------- */
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

/* ---------------- Shopify GraphQL helper ---------------- */
async function shopifyGraphQL(query, variables) {
  const res = await fetch(
    `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN
      },
      body: JSON.stringify({ query, variables })
    }
  );

  const json = await res.json();
  if (!res.ok || json.errors) {
    throw new Error(
      `Shopify GraphQL error: ${JSON.stringify(json.errors || json)}`
    );
  }
  return json.data;
}

const orderGid = (orderId) => `gid://shopify/Order/${orderId}`;
const productGid = (productId) => `gid://shopify/Product/${productId}`;

/* ---------------- Idempotency (order already sent?) ---------------- */
async function isOrderAlreadySent(orderId) {
  const q = `
    query($id: ID!) {
      order(id: $id) {
        sent: metafield(namespace:"bngc", key:"sent") { value }
      }
    }
  `;
  const data = await shopifyGraphQL(q, { id: orderGid(orderId) });
  return data.order?.sent?.value === "true";
}

/* ---------------- Store order metafields (NO codes) ---------------- */
async function setOrderMetafields(orderId, maskedRefs) {
  const m = `
    mutation($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) { userErrors { field message } }
    }
  `;

  const metafields = [
    {
      ownerId: orderGid(orderId),
      namespace: "bngc",
      key: "sent",
      type: "boolean",
      value: "true"
    },
    {
      ownerId: orderGid(orderId),
      namespace: "bngc",
      key: "reference_nos",
      type: "multi_line_text_field",
      value: maskedRefs.join("\n")
    },
    {
      ownerId: orderGid(orderId),
      namespace: "bngc",
      key: "sent_at",
      type: "date_time",
      value: new Date().toISOString()
    }
  ];

  const data = await shopifyGraphQL(m, { metafields });
  const errs = data.metafieldsSet?.userErrors || [];
  if (errs.length) throw new Error(`MetafieldsSet error: ${JSON.stringify(errs)}`);
}

/* ---------------- Read product metafields ---------------- */
async function getProductBngc(productId) {
  const q = `
    query($id: ID!) {
      product(id: $id) {
        enabled: metafield(namespace:"bngc", key:"enabled") { value }
        cost: metafield(namespace:"bngc", key:"cost_amount") { value }
      }
    }
  `;
  const data = await shopifyGraphQL(q, { id: productGid(productId) });
  const enabled = data.product?.enabled?.value === "true";
  const costAmount = data.product?.cost?.value ? Number(data.product.cost.value) : null;
  return { enabled, costAmount };
}

/* ---------------- Binance helpers ---------------- */
function signBinanceQuery(queryString, secret) {
  return crypto.createHmac("sha256", secret).update(queryString).digest("hex");
}

function maskRef(ref) {
  const s = String(ref || "");
  if (s.length <= 8) return "****";
  return s.slice(0, 4) + "****" + s.slice(-4);
}

async function createBinanceGiftCard({ token, amount }) {
  // TEST MODE: no Binance call (safe)
  if (TEST_MODE === "true") {
    return {
      success: true,
      data: {
        code: `TEST-CODE-${Math.floor(100000 + Math.random() * 900000)}`,
        referenceNo: `TEST-REF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        expiredTime: Date.now() + 30 * 24 * 60 * 60 * 1000
      }
    };
  }

  if (!BINANCE_API_KEY || !BINANCE_API_SECRET) {
    throw new Error("Missing Binance env vars (BINANCE_API_KEY/BINANCE_API_SECRET)");
  }

  const timestamp = Date.now();
  const params = new URLSearchParams({
    token,
    amount: String(amount),
    timestamp: String(timestamp)
  });

  const signature = signBinanceQuery(params.toString(), BINANCE_API_SECRET);
  const url =
    `https://api.binance.com/sapi/v1/giftcard/createCode?` +
    `${params.toString()}&signature=${signature}`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "X-MBX-APIKEY": BINANCE_API_KEY }
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Binance error ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

/* ---------------- Email (Zoho SMTP via Nodemailer) ---------------- */
function getSmtpTransporter() {
  const port = Number(SMTP_PORT || 587);
  const secure = String(SMTP_SECURE).toLowerCase() === "true";

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure, // true=465, false=587
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });
}

async function sendEmailSMTP({ to, subject, html }) {
  if (!SMTP_USER || !SMTP_PASS || !SENDER_EMAIL) {
    throw new Error("Missing SMTP env vars (SMTP_USER/SMTP_PASS/SENDER_EMAIL)");
  }

  const transporter = getSmtpTransporter();

  await transporter.sendMail({
    from: `"Shvilli" <${SENDER_EMAIL}>`,
    to,
    subject,
    html
  });
}

/* ---------------- Email HTML ---------------- */
function buildEmailHtml({ codes, amountPerCode, token = "USDT" }) {
  const codeLines = codes
    .map(
      (c) =>
        `<div style="font-size:18px;font-weight:bold;letter-spacing:1px;margin:6px 0;">${c}</div>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<body style="margin:0;background:#f3f4f6;">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:30px 0;">
<tr><td align="center">
<table width="100%" style="max-width:600px;background:#ffffff;border-radius:14px;font-family:Arial,Helvetica,sans-serif;overflow:hidden;">
<tr>
<td style="background:#9ca3af;padding:20px;text-align:center;">
  <a href="https://shvilli.com" target="_blank">
    <img src="https://shvilli.com/wp-content/uploads/2025/12/Logo_White.png"
         width="220" height="55" alt="Shvilli" style="display:block;margin:auto;">
  </a>
</td>
</tr>

<tr>
<td style="padding:30px;color:#111827;font-size:14px;line-height:1.6;">
<h2 style="text-align:center;margin-top:0;">Your Binance Gift Card</h2>
<p>Thank you for your purchase from <strong>Shvilli.com</strong>.</p>

<div style="background:#f3f4f6;padding:18px;border-radius:8px;text-align:center;margin:25px 0;">
  <div style="font-size:12px;color:#6b7280;margin-bottom:10px;">Gift Card Code(s)</div>
  ${codeLines}
</div>

<p><strong>Amount per code:</strong> ${amountPerCode} ${token}</p>
<p>Need help?
<a href="mailto:support@shvilli.com" style="color:#2563eb;text-decoration:none;">support@shvilli.com</a>
</p>
</td>
</tr>

<tr>
<td style="background:#f9fafb;padding:16px;text-align:center;font-size:13px;color:#6b7280;">
${new Date().getFullYear()} Shvilli.com – All rights reserved<br>
This is an automated email, please do not reply.
</td>
</tr>

</table>
</td></tr></table>
</body>
</html>`;
}

/* ---------------- Routes ---------------- */
app.get("/", (req, res) => res.send("BNGC server is running"));

app.post("/webhooks/orders_paid", async (req, res) => {
  try {
    // Basic checks
    if (!SHOPIFY_WEBHOOK_SECRET) return res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");
    if (!SHOPIFY_SHOP_DOMAIN || !SHOPIFY_ADMIN_TOKEN) return res.status(500).send("Missing Shopify env vars");

    // Verify Shopify signature
    if (!verifyShopifyWebhook(req)) return res.status(401).send("Invalid webhook signature");

    const order = JSON.parse(req.body.toString("utf8"));
    const orderId = order.id;

    // Idempotency
    if (await isOrderAlreadySent(orderId)) {
      console.log("Already processed order:", orderId);
      return res.status(200).send("Already sent");
    }

    const customerEmail = order.email || order.customer?.email;
    if (!customerEmail) {
      console.log("No customer email for order:", orderId);
      return res.status(200).send("No email");
    }

    const token = "USDT";
    const allCodes = [];
    const maskedRefs = [];
    let amountPerCodeForEmail = null;

    // Generate codes: qty => qty codes
    for (const item of order.line_items || []) {
      if (!item.product_id) continue;

      const { enabled, costAmount } = await getProductBngc(item.product_id);
      if (!enabled) continue;

      const qty = Math.max(1, Number(item.quantity || 1));
      const unitAmount = (costAmount && costAmount > 0) ? costAmount : Number(item.price || 0);
      if (!unitAmount || unitAmount <= 0) continue;

      amountPerCodeForEmail = unitAmount;

      for (let i = 0; i < qty; i++) {
        const result = await createBinanceGiftCard({ token, amount: unitAmount });
        if (!result?.success || !result?.data?.code) {
          throw new Error(`Giftcard failed: ${JSON.stringify(result)}`);
        }

        allCodes.push(result.data.code);
        maskedRefs.push(maskRef(result.data.referenceNo || "N/A"));
      }
    }

    if (!allCodes.length) {
      console.log("No bngc-enabled items in order:", orderId);
      return res.status(200).send("No giftcard items");
    }

    // Email only (Zoho SMTP)
    await sendEmailSMTP({
      to: customerEmail,
      subject: "Your Binance Gift Card from Shvilli",
      html: buildEmailHtml({
        codes: allCodes,
        amountPerCode: amountPerCodeForEmail ?? "N/A",
        token
      })
    });

    // Store references only (NO codes)
    await setOrderMetafields(orderId, maskedRefs);

    console.log("SUCCESS order:", orderId, "codes:", allCodes.length);
    return res.status(200).send("OK");
  } catch (e) {
    console.error("ERROR:", e?.message || e);
    return res.status(500).send("Error");
  }
});

app.listen(process.env.PORT || 3000, () => console.log("Server started"));
