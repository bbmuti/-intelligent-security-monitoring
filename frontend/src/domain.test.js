import { describe, expect, test } from "vitest";

import { filterAlerts, filterEvents, isActiveAlert } from "./domain.js";

const alerts = [
  { id: 1, status: "open", severity: "critical" },
  { id: 2, status: "investigating", severity: "high" },
  { id: 3, status: "resolved", severity: "critical" },
  { id: 4, status: "false_positive", severity: "medium" },
];

describe("dashboard domain filters", () => {
  test("active alerts exclude resolved and false-positive findings", () => {
    expect(alerts.filter(isActiveAlert)).toHaveLength(2);
  });

  test("alert filters combine status and severity", () => {
    expect(filterAlerts(alerts, "active", "critical").map((item) => item.id)).toEqual([1]);
  });

  test("event search matches user, IP and endpoint", () => {
    const events = [
      { id: 1, event_type: "login", user_id: "beren", ip_address: "10.0.0.2", endpoint: "/login" },
      { id: 2, event_type: "api_access", user_id: "admin", ip_address: "10.0.0.8", endpoint: "/api/users" },
    ];
    expect(filterEvents(events, "api_access", "users").map((item) => item.id)).toEqual([2]);
    expect(filterEvents(events, "all", "10.0.0.2").map((item) => item.id)).toEqual([1]);
  });
});
