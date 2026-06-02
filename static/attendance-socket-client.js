(function (window, document) {
    "use strict";

    function getText(value) {
        return value === null || value === undefined ? "" : String(value);
    }

    function makeCell(value) {
        var td = document.createElement("td");
        td.textContent = getText(value);
        return td;
    }

    function makeStatusCell(status) {
        var td = document.createElement("td");
        var badge = document.createElement("span");
        badge.className = "badge badge-green";
        badge.textContent = getText(status || "Present");
        td.appendChild(badge);
        return td;
    }

    function updateConnectionStatus(statusEl, state, message) {
        if (!statusEl) return;
        statusEl.dataset.state = state;
        statusEl.textContent = message;
    }

    function incrementDashboardCounts(statSelector) {
        var statVals = document.querySelectorAll(statSelector);
        if (statVals.length < 2) return;

        var present = parseInt(statVals[0].textContent, 10);
        var absent = parseInt(statVals[1].textContent, 10);

        if (!Number.isNaN(present)) {
            statVals[0].textContent = String(present + 1);
        }
        if (!Number.isNaN(absent)) {
            statVals[1].textContent = String(Math.max(0, absent - 1));
        }
    }

    function addAttendanceRow(config, data) {
        if (!data || data.faculty !== config.facultyUser) return;

        var tbody = document.querySelector(config.tableBodySelector);
        if (!tbody) return;

        var emptyRow = tbody.querySelector(".empty");
        if (emptyRow && emptyRow.parentNode) {
            emptyRow.parentNode.removeChild(emptyRow);
        }

        var tr = document.createElement("tr");
        tr.className = "attendance-row-live";
        tr.appendChild(makeCell(data.roll));
        tr.appendChild(makeCell(data.name));
        tr.appendChild(makeCell(data.course_id));
        tr.appendChild(makeStatusCell(data.status));
        tr.appendChild(makeCell(data.time));
        tbody.insertBefore(tr, tbody.firstChild);

        incrementDashboardCounts(config.statSelector);
    }

    function normalizeConfig(options) {
        options = options || {};
        return {
            facultyUser: options.facultyUser || "",
            tableBodySelector: options.tableBodySelector || "#attendance-body",
            statusSelector: options.statusSelector || "#attendance-socket-status",
            statSelector: options.statSelector || ".stat-val",
            socketUrl: options.socketUrl || "",
            socketPath: options.socketPath || "/socket.io"
        };
    }

    function start(options) {
        var config = normalizeConfig(options);
        var statusEl = document.querySelector(config.statusSelector);

        if (!window.io) {
            updateConnectionStatus(
                statusEl,
                "offline",
                "Live updates unavailable: Socket.IO client did not load."
            );
            return null;
        }

        updateConnectionStatus(statusEl, "connecting", "Connecting live updates...");

        var socketOptions = {
            path: config.socketPath,
            transports: ["websocket", "polling"],
            reconnection: true,
            reconnectionAttempts: Infinity,
            reconnectionDelay: 500,
            reconnectionDelayMax: 5000
        };

        var socket = config.socketUrl
            ? window.io(config.socketUrl, socketOptions)
            : window.io(socketOptions);

        socket.on("connect", function () {
            updateConnectionStatus(statusEl, "connecting", "Joining live attendance stream...");
            socket.emit("join_faculty_dashboard", {}, function (response) {
                if (response && response.ok) {
                    updateConnectionStatus(statusEl, "online", "Live attendance updates connected.");
                    return;
                }

                updateConnectionStatus(
                    statusEl,
                    "offline",
                    (response && response.error) || "Live updates could not join this dashboard."
                );
            });
        });

        socket.on("new_attendance", function (data) {
            addAttendanceRow(config, data);
        });

        socket.on("disconnect", function () {
            updateConnectionStatus(statusEl, "offline", "Live updates disconnected. Reconnecting...");
        });

        socket.io.on("reconnect_attempt", function () {
            updateConnectionStatus(statusEl, "connecting", "Reconnecting live updates...");
        });

        socket.on("connect_error", function () {
            updateConnectionStatus(statusEl, "offline", "Live updates connection failed.");
        });

        return socket;
    }

    window.AttendanceSocketClient = {
        start: start
    };

    function boot() {
        if (window.AMS_ATTENDANCE_SOCKET) {
            window.amsAttendanceSocket = start(window.AMS_ATTENDANCE_SOCKET);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})(window, document);
