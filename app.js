const vehicleCatalog = [
  { name: "VW Golf 1.5 TSI", consumption: 6.3, fuelType: "E10" },
  { name: "Toyota Yaris Hybrid", consumption: 4.2, fuelType: "E10" },
  { name: "BMW 320d", consumption: 5.4, fuelType: "Diesel" },
  { name: "Skoda Octavia Combi", consumption: 5.9, fuelType: "E5" },
  { name: "Mercedes C200", consumption: 6.8, fuelType: "E5" },
];

const fuelPriceApiUrl = "https://www.fueleconomy.gov/ws/rest/fuelprices";
const fallbackFuelPrices = {
  E5: 1.92,
  E10: 1.84,
  Diesel: 1.76,
};

const form = document.querySelector("#trip-form");
const vehicleSelect = document.querySelector("#vehicle");
const fuelTableBody = document.querySelector("#fuelTableBody");
const fuelStatus = document.querySelector("#fuelStatus");
const refreshPricesBtn = document.querySelector("#refreshPrices");
const calculationBox = document.querySelector("#calculation");
const tripTableBody = document.querySelector("#tripTableBody");
const clearHistoryBtn = document.querySelector("#clearHistory");

const currency = new Intl.NumberFormat("de-DE", {
  style: "currency",
  currency: "EUR",
});

let activeFuelPrices = { ...fallbackFuelPrices };

function fillVehicles() {
  vehicleCatalog.forEach((vehicle, idx) => {
    const option = document.createElement("option");
    option.value = String(idx);
    option.textContent = `${vehicle.name} (${vehicle.consumption} L/100km, ${vehicle.fuelType})`;
    vehicleSelect.append(option);
  });
}

function mapApiToFuelTypes(apiValues) {
  return {
    E5: Number(apiValues.premium || fallbackFuelPrices.E5),
    E10: Number(apiValues.regular || fallbackFuelPrices.E10),
    Diesel: Number(apiValues.diesel || fallbackFuelPrices.Diesel),
  };
}

async function fetchDailyFuelPrices() {
  const response = await fetch(fuelPriceApiUrl);
  if (!response.ok) {
    throw new Error(`API status ${response.status}`);
  }

  const xmlText = await response.text();
  const xml = new DOMParser().parseFromString(xmlText, "text/xml");
  const valueOf = (tagName) => xml.querySelector(tagName)?.textContent;

  return mapApiToFuelTypes({
    regular: valueOf("regular"),
    premium: valueOf("premium"),
    diesel: valueOf("diesel"),
  });
}

function renderFuelTable() {
  fuelTableBody.innerHTML = "";

  vehicleCatalog.forEach((vehicle) => {
    const tr = document.createElement("tr");
    const modelFuelPrice = activeFuelPrices[vehicle.fuelType];
    tr.innerHTML = `
      <td>${vehicle.name}</td>
      <td>${vehicle.fuelType}</td>
      <td>${currency.format(modelFuelPrice)}/L</td>
    `;
    fuelTableBody.append(tr);
  });
}

async function loadFuelPrices() {
  fuelStatus.textContent = "Preise werden geladen …";
  refreshPricesBtn.disabled = true;

  try {
    activeFuelPrices = await fetchDailyFuelPrices();
    fuelStatus.textContent =
      "Tagesaktuelle Preise erfolgreich geladen (Quelle: fueleconomy.gov, heute).";
  } catch (error) {
    activeFuelPrices = { ...fallbackFuelPrices };
    fuelStatus.textContent =
      "Live-Preise nicht erreichbar. Es werden Fallback-Preise für die Berechnung verwendet.";
    console.error("Fuel price fetch failed:", error);
  } finally {
    renderFuelTable();
    refreshPricesBtn.disabled = false;
  }
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
      <td>${currency.format(trip.fuelPricePerLiter)}/L</td>
      <td>${trip.distance.toFixed(1)} km</td>
      <td>${trip.consumption.toFixed(2)} L</td>
      <td>${currency.format(trip.totalCost)}</td>
      <td>${currency.format(trip.costPerKm)}</td>
    `;
    tripTableBody.append(tr);
  });

  if (trips.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="7">Noch keine Fahrten gespeichert.</td>';
    tripTableBody.append(tr);
  }
}

function calculateTrip({ modelIndex, distanceKm }) {
  const vehicle = vehicleCatalog[modelIndex];
  const fuelPricePerLiter = activeFuelPrices[vehicle.fuelType];
  const litersUsed = (distanceKm / 100) * vehicle.consumption;
  const totalCost = litersUsed * fuelPricePerLiter;
  const costPerKm = totalCost / distanceKm;

  return {
    model: vehicle.name,
    fuelType: vehicle.fuelType,
    fuelPricePerLiter,
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
  const date = document.querySelector("#tripDate").value;

  const result = calculateTrip({ modelIndex, distanceKm });

  calculationBox.innerHTML = `
    <strong>${result.model}</strong><br>
    Kraftstoff: ${result.fuelType} zu ${currency.format(result.fuelPricePerLiter)}/L<br>
    Verbrauch: ${result.litersUsed.toFixed(2)} L auf ${distanceKm.toFixed(1)} km<br>
    Gesamtkosten: ${currency.format(result.totalCost)}<br>
    Kosten pro Kilometer: ${currency.format(result.costPerKm)}
  `;

  const trips = getTrips();
  trips.unshift({
    date,
    model: result.model,
    fuelPricePerLiter: result.fuelPricePerLiter,
    distance: distanceKm,
    consumption: result.litersUsed,
    totalCost: result.totalCost,
    costPerKm: result.costPerKm,
  });

  saveTrips(trips);
  renderTrips();
});

refreshPricesBtn.addEventListener("click", loadFuelPrices);

clearHistoryBtn.addEventListener("click", () => {
  localStorage.removeItem("tripBookEntries");
  renderTrips();
  calculationBox.textContent = "Historie gelöscht. Neue Berechnung starten.";
});

fillVehicles();
setTodayDate();
renderTrips();
loadFuelPrices();
