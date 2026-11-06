// Draws the world map of traffic by destination country on the Network Statistics page.
(function () {
	// Fixed bands keep a circle's meaning the same in every period, however busy the top country is.
	var BANDS = [
		{limit: 10e6, label: "Under 10 MB", color: "#2699a6"},
		{limit: 100e6, label: "10 to 100 MB", color: "#1a7480"},
		{limit: 1e9, label: "100 MB to 1 GB", color: "#0f4f5a"},
		{limit: Infinity, label: "1 GB or more", color: "#062e36"}
	];
	// The map file identifies countries by ISO numeric code. Antarctica would only take up space.
	var ANTARCTICA = "010";
	var NARROW_WIDTH = 600;

	var card = document.getElementById("traffic_map");

	function getBand(bytes) {
		for (var i = 0; i < BANDS.length - 1; i++) {
			if (bytes < BANDS[i].limit) {
				return i;
			}
		}
		return BANDS.length - 1;
	}

	function formatBytes(bytes) {
		if (bytes >= 1e9) {
			return (bytes / 1e9).toFixed(1) + " GB";
		}
		if (bytes > 0 && bytes < 1e5) {
			return "under 0.1 MB";
		}
		return (bytes / 1e6).toFixed(1) + " MB";
	}

	function fetchJson(url) {
		return fetch(url).then(function (response) {
			if (!response.ok) {
				throw new Error(url + " returned " + response.status);
			}
			return response.json();
		});
	}

	// Splits the traffic into circles, largest first so small ones stay visible on top, and
	// countries that have no known position.
	function buildPoints(traffic, positions) {
		var points = [];
		var unplaced = {codes: [], bytes: 0};
		Object.keys(traffic).forEach(function (code) {
			var sent = traffic[code].sent;
			var received = traffic[code].received;
			var position = Object.prototype.hasOwnProperty.call(positions, code) ? positions[code] : null;
			if (!position) {
				unplaced.codes.push(code);
				unplaced.bytes += sent + received;
				return;
			}
			points.push({
				name: position[0],
				latitude: position[1],
				longitude: position[2],
				sent: sent,
				received: received,
				total: sent + received,
				value: getBand(sent + received) + 1
			});
		});
		points.sort(function (a, b) {
			return b.total - a.total;
		});
		return {points: points, unplaced: unplaced};
	}

	function showLegend(radii) {
		var legend = document.getElementById("traffic_map_legend");
		BANDS.forEach(function (band, index) {
			var item = document.createElement("li");
			var dot = document.createElement("span");
			var size = 2 * (radii[0] + (radii[1] - radii[0]) * index / (BANDS.length - 1));
			dot.className = "map-legend-dot";
			dot.style.width = size + "px";
			dot.style.height = size + "px";
			dot.style.backgroundColor = band.color;
			item.appendChild(dot);
			item.appendChild(document.createTextNode(band.label));
			legend.appendChild(item);
		});
	}

	function describeMap(points) {
		var top = points.slice(0, 5).map(function (point) {
			return point.name + " " + formatBytes(point.total);
		});
		return "World map of traffic by destination country. Highest volumes: " + top.join(", ") + ".";
	}

	function drawMap(atlas, points) {
		var canvas = document.getElementById("traffic_map_canvas");
		var countries = ChartGeo.topojson.feature(atlas, atlas.objects.countries).features.filter(function (feature) {
			return feature.id !== ANTARCTICA;
		});
		var radii = canvas.parentNode.clientWidth < NARROW_WIDTH ? [4, 12] : [6, 20];

		canvas.setAttribute("aria-label", describeMap(points));
		showLegend(radii);

		return new Chart(canvas.getContext("2d"), {
			type: "bubbleMap",
			data: {
				labels: points.map(function (point) {
					return point.name;
				}),
				datasets: [{
					outline: countries,
					showOutline: true,
					outlineBackgroundColor: "#eef0f1",
					outlineBorderColor: "#c9cfd1",
					outlineBorderWidth: 0.5,
					backgroundColor: function (context) {
						return context.raw ? BANDS[context.raw.value - 1].color + "d9" : BANDS[0].color;
					},
					// Separates circles that overlap, as they do across Western Europe.
					borderColor: "#ffffff",
					borderWidth: 1.5,
					hitRadius: 4,
					data: points
				}]
			},
			options: {
				animation: false,
				maintainAspectRatio: false,
				interaction: {mode: "nearest", intersect: true},
				plugins: {
					legend: {display: false},
					tooltip: {
						displayColors: false,
						callbacks: {
							title: function (items) {
								return items[0].raw.name;
							},
							label: function (item) {
								return [
									"Total: " + formatBytes(item.raw.total),
									"Sent: " + formatBytes(item.raw.sent),
									"Received: " + formatBytes(item.raw.received)
								];
							}
						}
					}
				},
				scales: {
					projection: {axis: "x", projection: "equalEarth"},
					// Each value is a band number, so the circle's size follows the same bands as its color.
					size: {axis: "x", display: false, mode: "radius", min: 1, max: BANDS.length, range: radii}
				}
			}
		});
	}

	function showUnplaced(unplaced) {
		if (unplaced.codes.length > 0) {
			var note = document.getElementById("traffic_map_unplaced");
			note.textContent = "Not on the map because their location is unknown: " + unplaced.codes.join(", ") +
				" (" + formatBytes(unplaced.bytes) + ").";
			note.hidden = false;
		}
	}

	function showError(message) {
		var state = document.getElementById("traffic_map_state");
		state.textContent = message;
		state.classList.add("error_message");
		state.hidden = false;
		card.querySelector(".chart-canvas-map").hidden = true;
	}

	function start() {
		if (typeof ChartGeo === "undefined") {
			showError("The map could not be loaded.");
			return;
		}
		Promise.all([fetchJson(card.dataset.mapUrl), fetchJson(card.dataset.positionsUrl)]).then(function (results) {
			var built = buildPoints(JSON.parse(card.dataset.traffic), results[1]);
			showUnplaced(built.unplaced);
			if (built.points.length === 0) {
				showError("None of the countries in this period could be placed on the map.");
				return;
			}
			drawMap(results[0], built.points);
		}).catch(function () {
			showError("The map could not be loaded.");
		});
	}

	if (card) {
		start();
	}
})();
