const form = document.getElementById("plannerForm");
const planOutput = document.getElementById("planOutput");
const yamlOutput = document.getElementById("yamlOutput");
const promptOutput = document.getElementById("promptOutput");

const baseBlocks = [
  { key: "Check-in", min: 5 },
  { key: "Aufwärmtraining", min: 10 },
  { key: "Crosstraining", min: 8 },
  { key: "Fitness ohne Geräte", min: 8 },
  { key: "Grundtechniken", min: 10 },
  { key: "Verteidigungstechniken", min: 10 },
  { key: "Rollenspiel/Simulation", min: 7 },
  { key: "Combatives/Military Drills", min: 7 },
  { key: "Mindset + Debrief", min: 5 },
];

const suggestions = {
  "Aufwärmtraining": ["Mobilität Hüfte/Schulter", "leichte Laufschule", "Reaktionssignale"],
  Crosstraining: ["Richtungswechsel", "Stop-and-Go", "Balance unter Störreiz"],
  "Fitness ohne Geräte": ["Squats", "Push-ups", "Plank-Varianten"],
  Grundtechniken: ["Stand & Deckung", "Distanzmanagement", "Jab/Cross oder Palm Strike"],
  Verteidigungstechniken: ["Befreiung aus Griff", "Abwehr + Gegenangriff", "Exit in sichere Distanz"],
  "Rollenspiel/Simulation": ["verbale Deeskalation", "Szenario mit Entscheidungsdruck", "Entkommen + Hilfe holen"],
  "Combatives/Military Drills": ["Intervall 20/20", "Kommando-Drill", "kurze Burst-Kombinationen"],
  "Mindset + Debrief": ["OODA kurz reflektieren", "Atemregulation", "1 Verbesserung fürs nächste Training"],
};

function distributeMinutes(total, intensity) {
  const blocks = baseBlocks.map((b) => ({ ...b, duration: b.min }));
  let remaining = total - blocks.reduce((sum, b) => sum + b.duration, 0);

  const priority =
    intensity === "Hoch"
      ? [5, 7, 2, 3, 6, 1, 4, 8, 0]
      : intensity === "Niedrig"
      ? [1, 4, 5, 8, 2, 3, 6, 7, 0]
      : [4, 5, 2, 3, 6, 7, 1, 8, 0];

  let idx = 0;
  while (remaining > 0) {
    blocks[priority[idx % priority.length]].duration += 1;
    idx += 1;
    remaining -= 1;
  }

  return blocks;
}

function buildPrompt(data) {
  return `Erstelle einen Krav-Maga-Kursplan auf Deutsch.
Rahmen:
- Zielgruppe: ${data.gruppe}
- Dauer: ${data.dauer} Minuten
- Niveau: ${data.niveau}
- Schwerpunkt: ${data.schwerpunkt}
- Intensität: ${data.intensitaet}
- Teilnehmer: ${data.teilnehmer}
- Einschränkungen: ${data.einschraenkungen || "keine"}

Pflichtblöcke:
Aufwärmtraining, Crosstraining, Fitnesstraining ohne Geräte,
Grundtechniken, Krav Maga Verteidigungstechniken,
Rollenspiele/Simulationen, Combatives oder Military Drills, Mindset + Debrief.

Gib aus:
1) Minutenplan je Block (Gesamtsumme exakt passend)
2) 3 konkrete Übungen pro Block
3) Coaching-Cues
4) Sicherheitsregeln
5) Skalierung für schwächer/stärker
6) 40-Minuten-Alternative`;
}

function toYaml(data, blocks) {
  const blockLines = blocks
    .map(
      (b) => `    - name: ${b.key}\n      dauer_min: ${b.duration}\n      inhalt: ${
        (suggestions[b.key] || []).join(", ") || "n/a"
      }`
    )
    .join("\n");

  return `kursplan:\n  gruppe: ${data.gruppe}\n  dauer_min: ${data.dauer}\n  niveau: ${data.niveau}\n  schwerpunkt: ${data.schwerpunkt}\n  intensitaet: ${data.intensitaet.toLowerCase()}\n  teilnehmer: ${data.teilnehmer}\n  einschraenkungen: ${data.einschraenkungen || "keine"}\n  bloecke:\n${blockLines}\n  regressionsvariante_40_min:\n    enthalten: true`;
}

function renderPlan(data, blocks) {
  const title = `Trainingsplan: ${data.gruppe} | ${data.dauer} Min | ${data.schwerpunkt}`;

  const list = blocks
    .map((b) => {
      const ex = suggestions[b.key] || [];
      return `<h3>${b.key} (${b.duration} Min)</h3><ul>${ex.map((e) => `<li>${e}</li>`).join("")}</ul>`;
    })
    .join("");

  const safety = `
  <h3>Sicherheitsregeln</h3>
  <ul>
    <li>Start/Stopp/Freeze-Kommandos klar kommunizieren.</li>
    <li>Partner nach Größe und Niveau matchen.</li>
    <li>Bei hoher Intensität zusätzliche Pause und Technikqualität priorisieren.</li>
  </ul>`;

  planOutput.innerHTML = `<h3>${title}</h3>${list}${safety}`;
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(form).entries());
  data.dauer = Number(data.dauer);

  const blocks = distributeMinutes(data.dauer, data.intensitaet);
  renderPlan(data, blocks);
  yamlOutput.textContent = toYaml(data, blocks);
  promptOutput.textContent = buildPrompt(data);
});

form.dispatchEvent(new Event("submit"));
