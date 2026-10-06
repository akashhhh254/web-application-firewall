/**
 * WAF SOC Dashboard Client-Side Helper
 * Handles auto-refresh telemetry, dynamic rule toggles, and log queries.
 */

document.addEventListener("DOMContentLoaded", () => {
    console.log("[WAF Sensor] Client telemetry initialized.");

    // Highlight row on click for investigation
    const logRows = document.querySelectorAll(".table-hover tbody tr");
    logRows.forEach(row => {
        row.addEventListener("click", () => {
            logRows.forEach(r => r.classList.remove("table-active"));
            row.classList.add("table-active");
        });
    });
});
