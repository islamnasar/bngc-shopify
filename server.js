app.get("/", (req, res) => {
  res.send("BNGC server is running ✅");
});
app.get("/ip", async (req, res) => {
  const r = await fetch("https://api.ipify.org?format=json");
  res.json(await r.json());
});
