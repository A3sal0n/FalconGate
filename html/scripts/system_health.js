// Draws the server health figures on the System Overview page and keeps them current.
(function(){
	var REFRESH_MS = 30000;
	var HIGH_PERCENT = 75;
	var CRITICAL_PERCENT = 90;

	var root = document.getElementById("system_health");
	var tiles = document.getElementById("health_tiles");
	var disks = document.getElementById("health_disks");
	var state = document.getElementById("health_state");
	var loading = false;
	var lastUpdated = null;

	function element(tag, className, text){
		var node = document.createElement(tag);
		if (className) {
			node.className = className;
		}
		if (text !== undefined) {
			node.textContent = text;
		}
		return node;
	}

	function formatBytes(bytes){
		var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
		var unit = 0;
		while (bytes >= 1024 && unit < units.length - 1) {
			bytes /= 1024;
			unit++;
		}
		return bytes.toFixed(unit === 0 ? 0 : 1) + " " + units[unit];
	}

	function formatUptime(seconds){
		var days = Math.floor(seconds / 86400);
		var hours = Math.floor((seconds % 86400) / 3600);
		var minutes = Math.floor((seconds % 3600) / 60);
		function part(value, name){
			return value + " " + name + (value === 1 ? "" : "s");
		}
		if (days > 0) {
			return part(days, "day") + ", " + part(hours, "hour");
		}
		if (hours > 0) {
			return part(hours, "hour") + ", " + part(minutes, "minute");
		}
		return part(minutes, "minute");
	}

	function severity(percent){
		if (percent >= CRITICAL_PERCENT) {
			return {name: "critical", label: "✖ Critical"};
		}
		if (percent >= HIGH_PERCENT) {
			return {name: "high", label: "▲ High"};
		}
		return {name: "normal", label: "✓ Normal"};
	}

	function meter(percent, label){
		var level = severity(percent);
		var track = element("div", "health-meter health-meter-" + level.name);
		track.setAttribute("role", "meter");
		track.setAttribute("aria-label", label);
		track.setAttribute("aria-valuemin", "0");
		track.setAttribute("aria-valuemax", "100");
		track.setAttribute("aria-valuenow", String(percent));
		track.title = percent + "%";
		var fill = element("div", "health-meter-fill");
		fill.style.width = Math.max(0, Math.min(100, percent)) + "%";
		track.appendChild(fill);
		return track;
	}

	function statusLabel(percent){
		var level = severity(percent);
		return element("span", "health-status health-status-" + level.name, level.label);
	}

	function tile(label, percent, detail, extra){
		var node = element("div", "health-tile");
		var header = element("div", "health-tile-header");
		header.appendChild(element("span", "health-tile-label", label));
		header.appendChild(statusLabel(percent));
		node.appendChild(header);
		node.appendChild(element("div", "health-tile-value", percent.toFixed(1) + "%"));
		node.appendChild(meter(percent, label));
		node.appendChild(element("p", "config-hint", detail));
		if (extra) {
			node.appendChild(element("p", "config-hint", extra));
		}
		return node;
	}

	function usageDetail(usage){
		return formatBytes(usage.used) + " used of " + formatBytes(usage.total) + ", " + formatBytes(usage.free) + " free";
	}

	function diskRow(disk){
		var row = element("div", "health-disk");
		var header = element("div", "health-disk-header");
		var name = element("div", "health-disk-name");
		name.appendChild(element("strong", "", disk.mount));
		name.appendChild(element("span", "config-hint", disk.device + " (" + disk.fstype + ")"));
		header.appendChild(name);
		var figures = element("div", "health-disk-figures");
		figures.appendChild(element("strong", "", disk.percent.toFixed(1) + "%"));
		figures.appendChild(statusLabel(disk.percent));
		header.appendChild(figures);
		row.appendChild(header);
		row.appendChild(meter(disk.percent, "Disk usage of " + disk.mount));
		row.appendChild(element("p", "config-hint", formatBytes(disk.used) + " used of " + formatBytes(disk.total) + ", " + formatBytes(disk.free) + " free"));
		return row;
	}

	function replaceChildren(parent, children){
		while (parent.firstChild) {
			parent.removeChild(parent.firstChild);
		}
		children.forEach(function(child){
			parent.appendChild(child);
		});
	}

	function render(health){
		var cpu = health.cpu;
		var cards = [
			tile("CPU usage", cpu.percent, cpu.cores + (cpu.cores === 1 ? " core" : " cores") + ", load " + cpu.load_1 + " / " + cpu.load_5 + " / " + cpu.load_15, "Up for " + formatUptime(health.uptime_seconds)),
			tile("Memory usage", health.memory.percent, usageDetail(health.memory))
		];
		if (health.swap.total > 0) {
			cards.push(tile("Swap usage", health.swap.percent, usageDetail(health.swap)));
		}
		replaceChildren(tiles, cards);

		if (health.disks.length > 0) {
			replaceChildren(disks, health.disks.map(diskRow));
		} else {
			replaceChildren(disks, [element("p", "config-hint", "No disk partitions were found.")]);
		}
	}

	function showState(message, failed){
		state.textContent = message;
		state.classList.toggle("health-state-error", failed);
	}

	function refresh(){
		if (loading) {
			return;
		}
		loading = true;
		fetch(root.getAttribute("data-url"), {credentials: "same-origin", cache: "no-store"})
			.then(function(response){
				return response.json().then(function(result){
					if (!response.ok) {
						throw new Error(result.error);
					}
					return result;
				});
			})
			.then(function(health){
				render(health);
				lastUpdated = health.updated;
				showState("Updated " + lastUpdated + ". Refreshes every 30 seconds.", false);
			})
			.catch(function(error){
				var reason = error.message || "The server health data could not be loaded.";
				showState(reason + (lastUpdated ? " Showing data from " + lastUpdated + "." : ""), true);
			})
			.then(function(){
				loading = false;
			});
	}

	var servicesRoot = document.getElementById("system_services");
	var serviceTiles = document.getElementById("service_tiles");
	var serviceErrors = document.getElementById("service_errors");
	var servicesState = document.getElementById("services_state");
	var loadingServices = false;
	var servicesUpdated = null;
	var LEVEL_ICONS = {normal: "✓", high: "▲", critical: "✖"};

	function serviceTile(service){
		var node = element("div", "service-tile service-tile-" + service.level);
		var header = element("div", "health-tile-header");
		header.appendChild(element("strong", "", service.name));
		header.appendChild(element("span", "health-status health-status-" + service.level, LEVEL_ICONS[service.level] + " " + service.label));
		node.appendChild(header);
		node.appendChild(element("p", "config-hint", service.description));
		var details = service.since ? "Since " + service.since : service.unit;
		if (service.restarts > 0) {
			details += ", restarted " + service.restarts + (service.restarts === 1 ? " time" : " times");
		}
		node.appendChild(element("p", "config-hint", details));
		return node;
	}

	function serviceErrorRows(services){
		var rows = [];
		services.forEach(function(service){
			if (!service.errors_available) {
				rows.push(element("p", "config-hint", service.name + ": the errors could not be read."));
			}
			service.errors.forEach(function(error){
				var row = element("div", "service-error");
				row.appendChild(element("strong", "", service.name));
				row.appendChild(element("span", "config-hint", error.time + (error.count > 1 ? ", repeated " + error.count + " times" : "")));
				row.appendChild(element("code", "", error.message));
				rows.push(row);
			});
		});
		return rows.length > 0 ? rows : [element("p", "config-hint", "✓ No errors have been reported since the services last started.")];
	}

	function showServicesState(message, failed){
		servicesState.textContent = message;
		servicesState.classList.toggle("health-state-error", failed);
	}

	function refreshServices(){
		if (loadingServices) {
			return;
		}
		loadingServices = true;
		fetch(servicesRoot.getAttribute("data-url"), {credentials: "same-origin", cache: "no-store"})
			.then(function(response){
				return response.json().then(function(result){
					if (!response.ok) {
						throw new Error(result.error);
					}
					return result;
				});
			})
			.then(function(status){
				replaceChildren(serviceTiles, status.services.map(serviceTile));
				replaceChildren(serviceErrors, serviceErrorRows(status.services));
				servicesUpdated = status.updated;
				showServicesState("Updated " + servicesUpdated + ". Refreshes every 30 seconds.", false);
			})
			.catch(function(error){
				var reason = error.message || "The service status could not be loaded.";
				showServicesState(reason + (servicesUpdated ? " Showing data from " + servicesUpdated + "." : ""), true);
			})
			.then(function(){
				loadingServices = false;
			});
	}

	refresh();
	refreshServices();
	setInterval(function(){
		refresh();
		refreshServices();
	}, REFRESH_MS);
})();
