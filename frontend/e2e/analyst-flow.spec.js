import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";

const capturePortfolioScreenshots = process.env.CAPTURE_PORTFOLIO_SCREENSHOTS === "1";

test("analyst can generate, inspect, and triage an explainable alert", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("e2e-admin-password");
  await page.getByRole("button", { name: "Enter analyst console" }).click();

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("button", { name: "Detection lab" }).click();
  const simulationResponse = page.waitForResponse((response) =>
    response.url().endsWith("/api/v1/simulations/brute_force") && response.request().method() === "POST"
  );
  await page.getByRole("button", { name: /Brute-force login/ }).click();
  expect((await simulationResponse).ok()).toBeTruthy();
  await expect(page.getByText(/\d+ events analyzed · \d+ alerts created/i)).toBeVisible({ timeout: 15_000 });

  if (capturePortfolioScreenshots) {
    await mkdir("portfolio-screenshots", { recursive: true });
    await page.getByRole("button", { name: "Overview" }).click();
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
    await page.screenshot({
      path: "portfolio-screenshots/dashboard-overview.png",
      fullPage: true,
    });
  }

  await page.getByRole("button", { name: /Alerts/ }).click();
  await page.getByRole("button", { name: /Possible brute-force authentication attack/ }).first().click();
  const dialog = page.getByRole("dialog", { name: "Possible brute-force authentication attack" });
  await expect(dialog).toContainText("T1110");
  if (capturePortfolioScreenshots) {
    await page.screenshot({
      path: "portfolio-screenshots/explainable-alert.png",
      fullPage: true,
    });
  }
  await dialog.getByLabel("Status").selectOption("investigating");
  await expect(dialog.getByLabel("Status")).toHaveValue("investigating");
});
