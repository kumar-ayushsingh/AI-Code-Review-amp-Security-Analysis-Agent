import puppeteer from 'puppeteer';

(async () => {
  const browser = await puppeteer.launch({ executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' });
  const page = await browser.newPage();
  
  // Set viewport to a typical desktop size
  await page.setViewport({ width: 1280, height: 1080 });
  
  try {
    // Navigate to the local dev server
    await page.goto('http://localhost:5173', { waitUntil: 'networkidle0' });
    
    // Expand the first finding card to see the syntax highlighting and explanation
    await page.evaluate(() => {
      const cards = document.querySelectorAll('button[aria-expanded="false"]');
      if (cards.length > 0) {
        cards[0].click();
      }
    });
    
    // Wait for the animation to expand the card
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Take the screenshot and save it to the artifacts directory
    await page.screenshot({ 
      path: 'C:/Users/Aayush/.gemini/antigravity/brain/f758b043-ddd3-4d8a-8406-83028465dbb6/portal_screenshot.png',
      fullPage: false 
    });
    
    console.log("Screenshot successfully saved.");
  } catch (err) {
    console.error("Failed to take screenshot:", err);
  } finally {
    await browser.close();
  }
})();
