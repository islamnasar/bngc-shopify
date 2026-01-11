import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import nodemailer from "nodemailer";

const app = express();

/**
 * IMPORTANT:
 * - We need raw body ONLY for /webhooks to verify Shopify webhook HMAC.
 * - For normal routes (OAuth), we can use default query parsing (no body needed).
 */
app.use("/webhooks", express.raw({ type: "application/json" }));

const {
  // Shopify OAuth (NEW)
  SHOPIFY_CLIENT_ID = "",
  SHOPIFY_CLIENT_SECRET = "",
  APP_URL = "https://bngc-shopify.onrender.com",

  // Shopify Webhook + Shop domain
  SHOPIFY_WEBHOOK_SECRET = "",
  SHOPIFY_SHOP_DOMAIN = "", // e.g. shvilli-2.myshopify.com

  // Optional legacy token (NOT required if OAuth used)
  SHOPIFY_ADMIN_TOKEN = "",

  // Binance
  BINANCE_API_KEY = "",
  BINANCE_API_SECRET = "",

  // Zoho SMTP
  SMTP_HOST = "smtp.zoho.com",
  SMTP_PORT = "587",
  SMTP_SECURE = "false", // false for 587, true for 465
  SMTP_USER = "",
  SMTP_PASS = "",
  SENDER_EMAIL = "",

  // Mode
  TEST_MODE = "true",
} = process.env;

/**
 * We'll store the OAuth access token in memory.
 * NOTE: If Render restarts, you'll need to re-install (or store in DB).
 */
let SHOPIFY_OAUTH_TOKEN = "";

/* ---------------- Utilities ---------------- */
function timingSafeEqualStr(a, b) {
  const aa = Buffer.from(String(a || ""), "utf8");
  const bb = Buffer.from(String(b || ""), "utf8");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

/* ---------------- Shopify Webhook HMAC verify ---------------- */
function verifyShopifyWebhook(req) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256") || "";
  const digest = crypto
    .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
    .update(req.body) // raw Buffer
    .digest("base64");

  return timingSafeEqualStr(digest, hmacHeader);
}

/* ---------------- OAuth HMAC verify (callback) ---------------- */
function verifyOAuthHmac(query) {
  // Shopify sends hmac as hex. We must build message from query params excluding hmac & signature.
  const { hmac, signature, ...rest } = query;

  const message = Object.keys(rest)
    .sort()
    .map((k) => `${k}=${Array.isArray(rest[k]) ? rest[k].join(",") : rest[k]}`)
    .join("&");

  const digest = crypto
    .createHmac("sha256", SHOPIFY_CLIENT_SECRET)
    .update(message)
    .digest("hex");

  return timingSafeEqualStr(digest, hmac);
}

/* ---------------- Shopify GraphQL helper ---------------- */
async function shopifyGraphQL(query, variables) {
  const tokenToUse = SHOPIFY_OAUTH_TOKEN || SHOPIFY_ADMIN_TOKEN;
  if (!tokenToUse) throw new Error("Missing Shopify access token (OAuth not installed yet)");

  const res = await fetch(`https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": tokenToUse,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.errors) {
    throw new Error(`Shopify GraphQL error: ${JSON.stringify(json.errors || json)}`);
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
      value: "true",
    },
    {
      ownerId: orderGid(orderId),
      namespace: "bngc",
      key: "reference_nos",
      type: "multi_line_text_field",
      value: maskedRefs.join("\n"),
    },
    {
      ownerId: orderGid(orderId),
      namespace: "bngc",
      key: "sent_at",
      type: "date_time",
      value: new Date().toISOString(),
    },
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

/**
 * Returns normalized shape:
 * { code, referenceNo, expiredTime }
 */
async function createBinanceGiftCard({ token, amount }) {
  // TEST MODE: no Binance call (safe)
  if (TEST_MODE === "true") {
    return {
      code: `TEST-CODE-${Math.floor(100000 + Math.random() * 900000)}`,
      referenceNo: `TEST-REF-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      expiredTime: Date.now() + 30 * 24 * 60 * 60 * 1000,
    };
  }

  if (!BINANCE_API_KEY || !BINANCE_API_SECRET) {
    throw new Error("Missing Binance env vars (BINANCE_API_KEY/BINANCE_API_SECRET)");
  }

  const timestamp = Date.now();
  const params = new URLSearchParams({
    token,
    amount: String(amount),
    timestamp: String(timestamp),
  });

  const signature = signBinanceQuery(params.toString(), BINANCE_API_SECRET);
  const url =
    `https://api.binance.com/sapi/v1/giftcard/createCode?` +
    `${params.toString()}&signature=${signature}`;

  const res = await fetch(url, {
    method: "POST",
    headers: { "X-MBX-APIKEY": BINANCE_API_KEY },
  });

  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Binance error ${res.status}: ${JSON.stringify(json)}`);

  // Binance typically returns { code, referenceNo, expiredTime, ... }
  if (!json.code) throw new Error(`Unexpected Binance response: ${JSON.stringify(json)}`);

  return {
    code: json.code,
    referenceNo: json.referenceNo || "",
    expiredTime: json.expiredTime || null,
  };
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
      pass: SMTP_PASS,
    },
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
    html,
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

// Health
app.get("/", (req, res) => res.send("BNGC server is running ✅"));

// Start OAuth install (open this)
app.get("/auth/shopify", (req, res) => {
  if (!SHOPIFY_SHOP_DOMAIN) return res.status(500).send("Missing SHOPIFY_SHOP_DOMAIN");
  if (!SHOPIFY_CLIENT_ID) return res.status(500).send("Missing SHOPIFY_CLIENT_ID");
  if (!APP_URL) return res.status(500).send("Missing APP_URL");

  const scopes = "read_orders,write_metafields";
  const redirectUri = `${APP_URL}/auth/shopify/callback`;
  const state = crypto.randomBytes(16).toString("hex");

  const installUrl =
    `https://${SHOPIFY_SHOP_DOMAIN}/admin/oauth/authorize` +
    `?client_id=${SHOPIFY_CLIENT_ID}` +
    `&scope=${encodeURIComponent(scopes)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${state}`;

  return res.redirect(installUrl);
});

// OAuth callback (Shopify redirects here)
app.get("/auth/shopify/callback", async (req, res) => {
  try {
    if (!SHOPIFY_CLIENT_ID || !SHOPIFY_CLIENT_SECRET) {
      return res.status(500).send("Missing SHOPIFY_CLIENT_ID/SHOPIFY_CLIENT_SECRET");
    }

    // Verify HMAC
    if (!verifyOAuthHmac(req.query)) {
      return res.status(401).send("HMAC verification failed");
    }

    const { code, shop } = req.query;
    if (!code || !shop) return res.status(400).send("Missing code/shop");

    // Exchange code -> access token
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: SHOPIFY_CLIENT_ID,
        client_secret: SHOPIFY_CLIENT_SECRET,
        code,
      }),
    });

    const tokenJson = await tokenRes.json().catch(() => ({}));
    if (!tokenRes.ok || !tokenJson.access_token) {
      return res.status(400).send(`Token error: ${JSON.stringify(tokenJson)}`);
    }

    SHOPIFY_OAUTH_TOKEN = tokenJson.access_token;

    return res
      .status(200)
      .send("Installed OK ✅ Shopify token saved in server memory. You can test webhook now.");
  } catch (e) {
    console.error("OAuth callback error:", e?.message || e);
    return res.status(500).send("OAuth callback error");
  }
});

// Shopify webhook: orders paid
app.post("/webhooks/orders_paid", async (req, res) => {
  try {
    if (!SHOPIFY_WEBHOOK_SECRET) return res.status(500).send("Missing SHOPIFY_WEBHOOK_SECRET");
    if (!SHOPIFY_SHOP_DOMAIN) return res.status(500).send("Missing SHOPIFY_SHOP_DOMAIN");

    // Must have token from OAuth OR legacy env token
    if (!SHOPIFY_OAUTH_TOKEN && !SHOPIFY_ADMIN_TOKEN) {
      return res.status(500).send("No Shopify access token. Install the app first: /auth/shopify");
    }

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
      const unitAmount =
        costAmount && costAmount > 0 ? costAmount : Number(item.price || 0);
      if (!unitAmount || unitAmount <= 0) continue;

      amountPerCodeForEmail = unitAmount;

      for (let i = 0; i < qty; i++) {
        const gc = await createBinanceGiftCard({ token, amount: unitAmount });

        allCodes.push(gc.code);
        maskedRefs.push(maskRef(gc.referenceNo || "N/A"));
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
        token,
      }),
    });

    // Store references only (NO codes)
    await setOrderMetafields(orderId, maskedRefs);

    console.log("SUCCESS order:", orderId, "codes:", allCodes.length);
    return res.status(200).send("OK");
  } catch (e) {
    console.error("WEBHOOK ERROR:", e?.message || e);
    return res.status(500).send("Error");
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server started ✅");
  console.log("Open install URL: /auth/shopify");
});
