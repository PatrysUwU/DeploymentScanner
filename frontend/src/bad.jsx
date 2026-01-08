// 1. Użycie eval() – klasyczny czerwony alarm
function dangerousEval(userInput) {
  return eval(userInput); // ESLint security: no-eval
}

// 2. Użycie Function() konstruktora – prawie tak samo niebezpieczne jak eval
const fn = new Function("return " + userInput); // no-new-func

// 3. Bezpośrednie użycie innerHTML z niezaufanymi danymi
element.innerHTML = userComment; // no-inner-html

// 4. Użycie document.write() – prawie zawsze zły pomysł
document.write("<div>" + userName + "</div>"); // no-document-write

// 5. Hardcoded credentials / sekretów w kodzie
const stripeKey = "sk_live_51Nabcdef1234567890"; // detect-object-injection + no-hardcoded-credentials (w nowszych wersjach)

// 6. Niebezpieczne użycie RegExp z niezaufanym wejściem
new RegExp("^" + userPattern + "$"); // no-unsafe-regex (może spowodować ReDoS)

// 7. Użycie requestAnimationFrame / setTimeout z stringiem zamiast funkcji
setTimeout("alert('hacked')", 100); // no-set-timeout-string (bardzo rzadko, ale wykrywa)

// 8. PostMessage bez weryfikacji origin
window.addEventListener("message", (event) => {
  // ... robimy coś z event.data bez sprawdzenia event.origin
}); // no-postmessage-origin-check (bardzo ważna reguła)

// 9. Użycie child_process.exec z niezaufanym wejściem (Node.js)
const { exec } = require("child_process");
exec(`git clone ${userRepoUrl}`); // no-exec-with-user-input (bardzo mocna reguła)

// 10. Object injection – niebezpieczne użycie [] lub . z niezaufanym kluczem
const prop = userInput;
const value = data[prop]; // detect-object-injection
