const vehicleCatalog = [
  { name: "VW Golf 1.5 TSI", consumption: 6.3 },
  { name: "Toyota Yaris Hybrid", consumption: 4.2 },
  { name: "BMW 320d", consumption: 5.4 },
  { name: "Skoda Octavia Combi", consumption: 5.9 },
  { name: "Mercedes C200", consumption: 6.8 },
];

const form = document.querySelector("#trip-form");
const vehicleSelect = document.querySelector("#vehicle");
const calculationBox = document.querySelector("#calculation");
const tripTableBody = document.querySelector("#tripTableBody");
const clearHistoryBtn = document.querySelector("#clearHistory");

const currency = new Intl.NumberFormat("de-DE", {
  style: "currency",
  currency: "EUR",
});

function fillVehicles() {
  vehicleCatalog.forEach((vehicle, idx) => {
    const option = document.createElement("option");
    option.value = String(idx);
    option.textContent = `${vehicle.name} (${vehicle.consumption} L/100km)`;
    vehicleSelect.append(option);
  });
}

function getTrips() {
  const raw = localStorage.getItem("tripBookEntries");
  return raw ? JSON.parse(raw) : [];
}

function saveTrips(trips) {
  localStorage.setItem("tripBookEntries", JSON.stringify(trips));
}

function renderTrips() {
  const trips = getTrips();
  tripTableBody.innerHTML = "";

  trips.forEach((trip) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${trip.date}</td>
      <td>${trip.model}</td>
      <td>${trip.distance.toFixed(1)} km</td>
      <td>${trip.consumption.toFixed(2)} L</td>
      <td>${currency.format(trip.totalCost)}</td>
      <td>${currency.format(trip.costPerKm)}</td>
    `;
    tripTableBody.append(tr);
  });

  if (trips.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6">Noch keine Fahrten gespeichert.</td>';
    tripTableBody.append(tr);
  }
}

function calculateTrip({ modelIndex, distanceKm, fuelPricePerLiter }) {
  const vehicle = vehicleCatalog[modelIndex];
  const litersUsed = (distanceKm / 100) * vehicle.consumption;
  const totalCost = litersUsed * fuelPricePerLiter;
  const costPerKm = totalCost / distanceKm;

  return {
    model: vehicle.name,
    litersUsed,
    totalCost,
    costPerKm,
  };
}

function setTodayDate() {
  const today = new Date().toISOString().split("T")[0];
  document.querySelector("#tripDate").value = today;
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const modelIndex = Number(vehicleSelect.value);
  const distanceKm = Number(document.querySelector("#distance").value);
  const fuelPricePerLiter = Number(document.querySelector("#fuelPrice").value);
  const date = document.querySelector("#tripDate").value;

  const result = calculateTrip({ modelIndex, distanceKm, fuelPricePerLiter });

  calculationBox.innerHTML = `
    <strong>${result.model}</strong><br>
    Verbrauch: ${result.litersUsed.toFixed(2)} L auf ${distanceKm.toFixed(1)} km<br>
    Gesamtkosten: ${currency.format(result.totalCost)}<br>
    Kosten pro Kilometer: ${currency.format(result.costPerKm)}
  `;

  const trips = getTrips();
  trips.unshift({
    date,
    model: result.model,
    distance: distanceKm,
    consumption: result.litersUsed,
    totalCost: result.totalCost,
    costPerKm: result.costPerKm,
  });

  saveTrips(trips);
  renderTrips();
});

clearHistoryBtn.addEventListener("click", () => {
  localStorage.removeItem("tripBookEntries");
  renderTrips();
  calculationBox.textContent = "Historie gelöscht. Neue Berechnung starten.";
});

fillVehicles();
setTodayDate();
renderTrips();
