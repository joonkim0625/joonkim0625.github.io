---
title: SANS Holiday Hack Challenge Elf Connect
date: 2024-12-10 22:41:30 
categories: [Cybersecurity, Ethical Hacking, Web Application Security]
tags:
  [javaScript, burp suite, session storage, web browser debugging tools]
---

## Hacking a JavaScript Game

Referring to [this video](https://www.youtube.com/watch?v=XsEqZvrTyoU&t=126s).

---

## Examination

This is a web-based game, so we begin by inspecting the game page using the browser's developer tools.

### Inspecting the Game

Open the browser's developer tools and navigate to the debugger section. This section displays all the files associated with the page you are inspecting.

![Debugger Section](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/debugger.png)

You can view the HTML source code of the Elf Connect game here:

![Game Code](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/game-code.png)

The console allows you to test various commands. When using the console, ensure you change the context from `top` to the specific target you are testing.

![Console Context](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/console-context.png)

### Attempt to Use the Tampermonkey Script

I attempted to use the Tampermonkey script provided by the video’s author to interact with the `iframe` object in a new tab, but this did not work for me. Right-clicking the `iframe` revealed an option to open it in a new tab, but further attempts to use the script were unsuccessful.

### Understanding Game Logic

By examining the game logic, I identified two key variables: `wordSets` and `correctSets`:

![Variables in Game Logic](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/way1.png)

Using these variables, you can deduce the combinations of words required to solve the puzzle. The video demonstrates how to use ChatGPT to generate a short JavaScript script that outputs the correct combinations for each round. Additionally, the video author writes a brief script to automate solving the game.

### Beating the High Score

Solving the puzzle alone does not guarantee beating the high score:

![High Score](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/high-score.png)

To achieve a higher score, you need to tamper with the values stored in `sessionStorage`. Initially, I considered intercepting the requests and modifying the score within the payload. However, the video showcased a simpler method: directly updating the score variable using the console. Since everything runs client-side without validation checks for tampered values, this approach works effectively.

![Score Tampering](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/score-tampering.png)

---

## Using Burp Suite

To capture and modify the game’s responses, you can use Burp Suite. Adjust the proxy settings to intercept the response from the server.

![Burp Response Capture](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/burp-resp-capture.png)

After forwarding the modified HTML code, the score begins at 55,000:

![Modified Score](https://joonkim0625.github.io/images/sans-holiday-hack/elf-connect/after-score.png)

This method eliminates the need to manipulate session storage values directly.

---

With these techniques, you can explore various ways to manipulate the game’s behavior and achieve your desired outcome.




