chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === "getCookies") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0].url;

      chrome.cookies.getAll({ url }, (cookies) => {
        sendResponse({ cookies });
      });
    });

    // Keep the message channel open for async response
    return true;
  }
});

