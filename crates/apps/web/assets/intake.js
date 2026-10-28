// Posts the chosen export file to /intake/ingest and shows the gate's verdict as plain text.
const form = document.getElementById("gate-form");
const input = document.getElementById("gate-file");
const out = document.getElementById("gate-result");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = input.files[0];
  if (!file) {
    out.textContent = "Choose an export file first.";
    return;
  }
  out.textContent = "Running the gate...";
  try {
    const response = await fetch("/intake/ingest", { method: "POST", body: await file.arrayBuffer() });
    const v = await response.json();
    if (!v.ok) {
      out.textContent = "Not processed: " + v.error;
      return;
    }
    const lines = ["Gate state: " + v.state];
    if (v.rejection_stage) lines.push("Rejected at stage: " + v.rejection_stage);
    if (v.rejection_code) lines.push("Rejection code: " + v.rejection_code);
    lines.push("Receipts: " + v.receipts);
    lines.push("Landed " + v.landed + ", duplicates " + v.duplicates + ", held " + v.held + ", conflicts " + v.conflicts + ", observations " + v.observations + ", loss entries " + v.losses);
    lines.push("Reload the page to see it under the tabs below.");
    out.textContent = lines.join("\n");
  } catch (e) {
    out.textContent = "The request failed: " + e;
  }
});
