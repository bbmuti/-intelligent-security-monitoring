import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { AlertDrawer, InitialLoadState } from "./components.jsx";

afterEach(cleanup);

describe("initial dashboard state", () => {
  test("shows the API error and offers a working retry", () => {
    const retry = vi.fn();
    render(<InitialLoadState error="API unavailable" onRetry={retry} />);
    expect(screen.getByRole("alert")).toHaveTextContent("API unavailable");
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(retry).toHaveBeenCalledOnce();
  });

  test("announces loading to assistive technology", () => {
    render(<InitialLoadState error="" onRetry={() => {}} />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading security telemetry");
  });
});

describe("alert details dialog", () => {
  const alert = {
    id: 7,
    title: "Possible brute-force authentication attack",
    severity: "high",
    risk_score: 78,
    explanation: "Risk increased because repeated failures were observed.",
    evidence: ["Five failed logins"],
    mitre_technique: "T1110 — Brute Force",
    status: "open",
  };

  test("has dialog semantics and closes with Escape", () => {
    const close = vi.fn();
    render(<AlertDrawer alert={alert} onClose={close} onStatus={() => {}} severityBadge={<span>high</span>} />);
    expect(screen.getByRole("dialog", { name: alert.title })).toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalledOnce();
  });

  test("sends status changes to the alert callback", () => {
    const update = vi.fn();
    render(<AlertDrawer alert={alert} onClose={() => {}} onStatus={update} severityBadge={<span>high</span>} />);
    fireEvent.change(screen.getByLabelText("Status"), { target: { value: "investigating" } });
    expect(update).toHaveBeenCalledWith(7, "investigating");
  });
});
