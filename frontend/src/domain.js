export const ACTIVE_STATUSES = new Set(["open", "investigating"]);

export function isActiveAlert(alert) {
  return ACTIVE_STATUSES.has(alert.status);
}

export function filterAlerts(alerts, status, severity) {
  return alerts.filter((alert) => {
    const statusMatches = status === "all"
      || (status === "active" ? isActiveAlert(alert) : alert.status === status);
    const severityMatches = severity === "all" || alert.severity === severity;
    return statusMatches && severityMatches;
  });
}

export function filterEvents(events, type, query) {
  const normalized = query.trim().toLowerCase();
  return events.filter((event) => {
    const typeMatches = type === "all" || event.event_type === type;
    const haystack = `${event.user_id} ${event.ip_address} ${event.endpoint}`.toLowerCase();
    return typeMatches && haystack.includes(normalized);
  });
}
