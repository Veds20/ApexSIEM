export const severityColor = {
  HIGH: "#b84636",
  MEDIUM: "#a97619",
  LOW: "#73856b",
  CRITICAL: "#b84636",
  INFORMATIONAL: "#707168",
};

export const severityClass = {
  HIGH: "severity-high",
  CRITICAL: "severity-high",
  MEDIUM: "severity-medium",
  LOW: "severity-low",
  INFORMATIONAL: "severity-unknown",
};

export const pretty = (value) =>
  value ? String(value).replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase()) : "Not present in telemetry";

export const when = (value) => {
  if (!value) return "Timestamp unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
};