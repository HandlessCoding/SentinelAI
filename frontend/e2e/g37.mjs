import assert from 'node:assert/strict'
import { appendFile, rename, writeFile } from 'node:fs/promises'
import AxeBuilder from '@axe-core/playwright'
import { chromium, expect } from '@playwright/test'

const [origin, log, csv] = process.argv.slice(2)
assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/)

function flow(index) {
  return (
    JSON.stringify({
      uid: 'CG37' + index,
      ts: 1700000000 + index,
      proto: 'tcp',
      conn_state: 'SF',
      'id.orig_h': '192.0.2.1',
      'id.orig_p': 40000 + index,
      'id.resp_h': '192.0.2.2',
      'id.resp_p': 443,
    }) + '\n'
  )
}

async function traffic(page) {
  await writeFile(log, Array.from({ length: 30 }, (_, index) => flow(index + 1)).join(''))
  await expect
    .poll(async () => {
      const response = await page.request.get(origin + '/api/traffic/summary')
      return (await response.json()).total_flows
    })
    .toBe(30)
  await page.goto(origin + '/#traffic')
  await page.keyboard.press('Tab')
  await expect(page.getByRole('link', { name: 'Skip to main content' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('main')).toBeFocused()
  const flowTable = page.getByRole('region', { name: 'Flow table' })
  const links = flowTable.getByRole('link')
  await expect(links).toHaveCount(25)
  const first = await links.evaluateAll((items) => items.map((item) => item.getAttribute('href')))

  await page.route(
    (url) => url.pathname === '/api/traffic/flows' && url.searchParams.has('cursor'),
    async (route) => {
      await appendFile(log, flow(31))
      await expect
        .poll(async () => {
          const response = await page.request.get(origin + '/api/traffic/summary')
          return (await response.json()).total_flows
        })
        .toBe(31)
      await route.continue()
    },
    { times: 1 },
  )
  await page.getByRole('button', { name: 'Next', exact: true }).click()
  await expect(links).toHaveCount(5)
  const second = await links.evaluateAll((items) => items.map((item) => item.getAttribute('href')))
  assert.equal(new Set([...first, ...second]).size, 30)
  await expect(flowTable).not.toContainText('40031')
  await page.getByRole('button', { name: 'Previous', exact: true }).click()
  await expect(links).toHaveCount(25)
  assert.deepEqual(await links.evaluateAll((items) => items.map((item) => item.getAttribute('href'))), first)

  await expect(async () => {
    await rename(log, log + '.1')
  }).toPass({ timeout: 3000, intervals: [25, 100] })
  await writeFile(log, flow(32))
  await expect
    .poll(async () => {
      const response = await page.request.get(origin + '/api/traffic/monitoring')
      const health = await response.json()
      const source = health.sources[0]
      return [health.recent_flows, Boolean(source?.last_drained_file), source?.backlog_bytes]
    })
    .toEqual([32, true, 0])

  await page.getByRole('button', { name: 'Resume live' }).click()
  const newest = flowTable.getByRole('row').filter({ hasText: '40032' }).getByRole('link')
  await expect(newest).toBeVisible()
  await expect(flowTable.getByRole('cell', { name: '192.0.2.1:40031' })).toBeVisible()
  await newest.focus()
  await page.keyboard.press('Enter')
  const detail = page.getByRole('complementary', { name: 'Flow details' })
  await expect(detail).toContainText('40032')
  await expect(page.getByRole('link', { name: 'Close flow details' })).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(detail).toBeHidden()
  await expect(newest).toBeFocused()
}

async function verifyAccessibility(page) {
  const result = await new AxeBuilder({ page }).analyze()
  const serious = result.violations.filter((item) => ['serious', 'critical'].includes(item.impact))
  assert.deepEqual(
    serious.map((item) => ({ rule: item.id, targets: item.nodes.map((node) => node.target) })),
    [],
  )
}

async function csvAndNavigation(page) {
  await page.getByRole('link', { name: 'Analyze', exact: true }).click()
  await page.getByRole('tab', { name: 'CSV upload' }).click()
  await page.getByLabel('CSV file').setInputFiles(csv)
  await page.getByRole('button', { name: 'Analyze CSV' }).click()
  await expect(page.getByText('5 of 5 records scored')).toBeVisible()
  const writes = []
  await page.route('**/api/analyze', async (route) => {
    const response = await route.fetch({ maxRetries: 0 })
    writes.push({
      status: response.status(),
      key: route.request().headers()['idempotency-key'],
      alerts: (await response.json()).alert_ids,
      payload: route.request().postDataJSON(),
    })
    if (writes.length === 2) await route.abort()
    else await route.fulfill({ response })
  })
  const save = page.getByRole('button', { name: 'Save suspected alerts' })
  await save.click()
  await expect(page.getByRole('alert')).toContainText('Saving stopped')
  await save.click()
  await expect(page.getByRole('heading', { name: 'CSV analysis saved' })).toBeVisible()
  assert.deepEqual(
    writes.map((write) => write.status),
    [201, 201, 200],
  )
  assert.ok(writes[0].key && writes[1].key)
  assert.notEqual(writes[0].key, writes[1].key)
  assert.equal(writes[1].key, writes[2].key)
  assert.deepEqual(writes[1].alerts, writes[2].alerts)
  const conflicting = writes[2].payload
  conflicting.records[0].dur = '100'
  const conflict = await page.request.post(origin + '/api/analyze', {
    headers: { 'Idempotency-Key': writes[2].key },
    data: conflicting,
  })
  assert.equal(conflict.status(), 409)
  await verifyAccessibility(page)
  await page.getByRole('link', { name: 'Alerts', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: 'Alerts', exact: true })).toBeVisible()
  await verifyAccessibility(page)
  await page.getByRole('link', { name: 'Incidents', exact: true }).focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('link', { name: 'New incident' })).toBeVisible()
  await verifyAccessibility(page)
  await incidentWorkflow(page)
}

async function fillIncident(page, title) {
  await page.getByRole('link', { name: 'New incident' }).click()
  await page.getByLabel('Title', { exact: true }).fill(title)
  await page.getByRole('checkbox').first().check()
}

async function incidentWorkflow(page) {
  await fillIncident(page, 'Synthetic rotation review')
  await page.getByRole('button', { name: 'Create incident' }).click()
  await page.getByRole('link', { name: 'View notes' }).click()
  await page.getByLabel('Analyst name').fill('Fixture analyst')
  await page.getByLabel('Investigation note').fill('Verified synthetic receipt recovery.')
  await page.getByRole('button', { name: 'Add note' }).click()
  await expect(page.getByText('Verified synthetic receipt recovery.')).toBeVisible()
  await page.reload()
  await expect(page.getByText('Verified synthetic receipt recovery.')).toBeVisible()

  await page.goto(origin + '/#incidents/00000000-0000-0000-0000-000000000000')
  await expect(page.getByText('Could not load incident', { exact: true })).toBeVisible()
  await expect(page.getByRole('link', { name: /Synthetic rotation review/ })).toBeVisible()

  await fillIncident(page, 'Late synthetic incident')
  const committed = Promise.withResolvers()
  const release = Promise.withResolvers()
  await page.route(
    '**/api/incidents',
    async (route) => {
      const response = await route.fetch()
      committed.resolve(response.status())
      await release.promise
      await route.fulfill({ response })
    },
    { times: 1 },
  )
  await page.getByRole('button', { name: 'Create incident' }).click()
  assert.equal(await committed.promise, 201)
  await page.getByRole('link', { name: 'Alerts', exact: true }).click()
  const finished = page.waitForResponse(
    (response) => response.url().endsWith('/api/incidents') && response.request().method() === 'POST',
  )
  release.resolve()
  await (await finished).finished()
  await expect(page).toHaveURL(origin + '/#alerts')
  await page.getByRole('link', { name: 'Incidents', exact: true }).click()
  await expect(page.getByRole('link', { name: /Late synthetic incident/ })).toBeVisible()
}

const browser = await chromium.launch()
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 960 } })
  const page = await context.newPage()
  await traffic(page)
  await verifyAccessibility(page)
  await csvAndNavigation(page)
  await page.setViewportSize({ width: 390, height: 844 })
  const menu = page.getByRole('button', { name: 'Open navigation' })
  await menu.focus()
  await page.keyboard.press('Enter')
  const navigation = page.getByRole('navigation')
  await expect(navigation.getByRole('link', { name: 'Incidents', exact: true })).toBeFocused()
  const brand = page.locator('#workspace-sidebar .brand')
  await brand.focus()
  await page.keyboard.press('Shift+Tab')
  await expect(navigation.getByRole('link').last()).toBeFocused()
  await page.keyboard.press('Tab')
  await expect(brand).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(menu).toBeFocused()
  console.log('G37 browser verification passed')
} finally {
  await browser.close()
}
