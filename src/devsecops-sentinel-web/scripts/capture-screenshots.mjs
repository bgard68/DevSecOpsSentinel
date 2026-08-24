/**
 * Regenerates the product screenshots in docs/assets/screenshots.
 *
 * These images had gone stale twice in a single day — once when severity
 * serialization was fixed and the risk label changed, once when the release
 * version in the header moved — because they were captured by hand. Driving them
 * from a script makes them a build artifact rather than a memory of what the
 * application looked like at some point.
 *
 * Expects the API and the dev server to be running. scripts/capture-screenshots.ps1
 * starts both, runs this, and stops them again.
 */
import { chromium } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const outputDirectory = resolve(here, '../../../docs/assets/screenshots');
const baseUrl = process.env.SENTINEL_WEB_URL ?? 'http://localhost:5173';

// Wide enough for the two-column analysis layout, tall enough that the result
// panel is not cut off. Fixed so successive runs are comparable.
const viewport = { width: 1440, height: 1080 };

async function capture(page, name) {
  const path = resolve(outputDirectory, name);
  await page.screenshot({ path, fullPage: false });
  console.log(`  captured ${name}`);
}

/** Waits for the analysis result panel rather than a fixed delay. */
async function analyze(page, buttonName) {
  const button = page.getByRole('button', { name: buttonName });
  await button.waitFor({ state: 'visible' });
  await page.waitForFunction(
    (label) => {
      const match = [...document.querySelectorAll('button')].find(
        (element) => element.textContent?.trim() === label,
      );
      return match instanceof HTMLButtonElement && !match.disabled;
    },
    buttonName,
  );
  await button.click();
  await page.getByRole('button', { name: /^Findings/ }).waitFor({ state: 'visible' });
}

async function main() {
  await mkdir(outputDirectory, { recursive: true });

  const browser = await chromium.launch();
  const context = await browser.newContext({
    viewport,
    deviceScaleFactor: 2, // Legible on a high-density display and in the README.
    colorScheme: 'dark',
  });

  const page = await context.newPage();

  try {
    // 1 — connected dashboard, before any analysis has run.
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('tab', { name: 'Simulation' }).waitFor();
    await capture(page, '01-connected-dashboard.png');

    // 2 — a Critical finding explained by the live model. script-injection is
    // the scenario that isolates a single Critical, so the panel is readable.
    // Controls are addressed by id: "Workflow file" labels an input in
    // Simulation mode and a select in GitHub mode, so the label is ambiguous.
    await page.locator('#scenario').selectOption('script-injection');
    await page.getByLabel('Include AI explanation').check();
    await analyze(page, 'Analyze workflow');
    await page.getByRole('button', { name: 'AI advisor' }).click();
    await page.getByText('Advisory only').waitFor();
    await capture(page, '02-live-ai-vulnerable-workflow.png');

    // 3 — the safe workflow read from GitHub, which must return nothing. This is
    // the claim that the model agrees with the engine rather than inventing work.
    await page.getByRole('tab', { name: 'GitHub Sandbox' }).click();
    await page.getByText('GitHub App connected').waitFor();

    await page
      .locator('#github-workflow')
      .selectOption('.github/workflows/safe.yml');

    // Selecting a repository, then a workflow, then its content is three chained
    // requests. Waiting for the content itself is the precondition the analyze
    // button actually has.
    await page.waitForFunction(() => {
      const yaml = document.querySelector('#workflow');
      return yaml instanceof HTMLTextAreaElement && yaml.value.includes('persist-credentials');
    });

    await page.getByLabel('Include AI explanation').check();
    await analyze(page, 'Analyze GitHub workflow');
    await page.getByRole('button', { name: 'AI advisor' }).click();
    await page.getByText('Advisory only').waitFor();
    await capture(page, '03-live-ai-safe-workflow.png');

    // 4 — the scanner scanning its own repository through the public tab. The
    // three findings that come back are the documented, test-enforced
    // exceptions from RepositoryWorkflowsTests, which is the point of the
    // image: the tool does not hide its own findings. Needs no key and spends
    // nothing — the fetch is anonymous.
    await page.getByRole('tab', { name: /Public repo/ }).click();
    await page.getByLabel('Public repository').fill('bgard68/DevSecOpsSentinel');
    await page.getByRole('button', { name: 'Scan public repository' }).click();
    await page.getByText('ci.yml', { exact: true }).waitFor({ timeout: 60_000 });
    await capture(page, '04-public-repo-self-scan.png');
  } finally {
    await browser.close();
  }
}

await main();
console.log('Screenshots regenerated.');
