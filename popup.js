document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scanCookies");
  const tbody = document.querySelector("#cookieTable tbody");
  const resultDiv = document.getElementById("result");

  scanBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "getCookies" }, (response) => {
      const cookies = response.cookies || [];
      tbody.innerHTML = "";
      let unsafeCount = 0;

      cookies.forEach(c => {
        if (!c.secure || !c.httpOnly || c.sameSite === "no_restriction") unsafeCount++;

        let sameSiteDisplay;
        switch(c.sameSite) {
          case "no_restriction": sameSiteDisplay = "None"; break;
          case "lax": sameSiteDisplay = "Lax"; break;
          case "strict": sameSiteDisplay = "Strict"; break;
          default: sameSiteDisplay = "Unspecified"; break;
        }

        const row = document.createElement("tr");
        row.innerHTML = `
          <td>${c.name}</td>
          <td>${c.secure ? "&#10003;" : "&#10007;"}</td>
          <td>${c.httpOnly ? "&#10003;" : "&#10007;"}</td>
          <td>${sameSiteDisplay}</td>
        `;
        tbody.appendChild(row);
      });

      // Determine overall risk/conclusion
      let conclusion;
      if (unsafeCount === 0) conclusion = "Safe 👍 — all cookies are secure.";
      else if (unsafeCount <= 2) conclusion = "Moderate ⚠️ — some cookies lack security attributes.";
      else conclusion = "Risky ❌ — several cookies may expose security issues.";

      resultDiv.innerHTML = `<b>Conclusion:</b> ${conclusion}`;
    });
  });
});
