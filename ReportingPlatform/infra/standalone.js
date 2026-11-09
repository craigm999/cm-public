const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); let bad = 0;
  for (const f of ['Entra/AppSignInDashboard.html', 'Entra/CAPolicyDashboard.html', 'Entra/LeastPrivilegeDashboard.html', 'Azure/AzureChangeDashboard.html']) {
    const p = await b.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
    await p.goto('file:///home/user/cm-public/' + f); await p.click('#btnSample'); await p.waitForTimeout(400);
    const tiles = (await p.textContent('#tiles')).trim().length;
    if (errs.length || !tiles) { bad++; console.log('BAD', f, errs); }
  }
  await b.close(); process.exit(bad);
})();
