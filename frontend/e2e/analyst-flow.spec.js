import { expect, test } from "@playwright/test";

test("analyst can generate, inspect, and triage an explainable alert", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("e2e-admin-password");
  await page.getByRole("button", { name: "Enter analyst console" }).click();

  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("button", { name: "Detection lab" }).click();
  await page.getByRole("button", { name: /Brute-force login/ }).click();
  await expect(page.getByText(/events analyzed/)).toBeVisible();

  await page.getByRole("button", { name: /Alerts/ }).click();
  await page.getByRole("button", { name: /Possible brute-force authentication attack/ }).first().click();
  const dialog = page.getByRole("dialog", { name: "Possible brute-force authentication attack" });
  await expect(dialog).toContainText("T1110");
  await dialog.getByLabel("Status").selectOption("investigating");
  await expect(dialog.getByLabel("Status")).toHaveValue("investigating");
});
