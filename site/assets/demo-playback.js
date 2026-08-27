// Terminal playback of the real `andon demo tamper` output.
//
// The text is not in this file. It lives in the page, verbatim, in the hidden
// <pre id="demo-source">, so that a reader without JavaScript, a reader who asked
// for reduced motion, and a search engine all get the same final frame this
// player types out. This file only decides the pace and lights the lamp.
//
// The lamp follows the transcript rather than a script of its own: it changes
// state on the lines the verifier actually prints ("attestation   confirmed",
// "attestation   divergent"), so it cannot claim an outcome the demo did not
// reach.

(function () {
  "use strict";

  var source = document.getElementById("demo-source");
  var screen = document.getElementById("demo-screen");
  var lamp = document.getElementById("lamp");
  var replay = document.getElementById("demo-replay");
  var skip = document.getElementById("demo-skip");
  var status = document.getElementById("demo-status");
  if (!source || !screen || !lamp) return;

  var lines = source.textContent.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n");

  // Without JavaScript the verbatim source is what a reader sees. With it, the
  // player takes over the same box and the source stays in the document.
  source.hidden = true;
  screen.hidden = false;

  // The same answer whether the request came from the OS, the page, or the URL.
  function reducedMotion() {
    var html = document.documentElement;
    if (html.getAttribute("data-motion") === "off") return true;
    try {
      return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    } catch (e) {
      return false;
    }
  }

  var LAMP = {
    idle: { label: "line running", sub: "nothing measured yet" },
    "self-report": { label: "self-reported · unwitnessed", sub: "counts downstream: no — a claim nobody has checked" },
    confirmed: { label: "confirmed", sub: "counts downstream: yes — the recompute agreed" },
    divergent: { label: "line stopped · divergent", sub: "counts downstream: no — the recompute disagreed, and named where" }
  };

  function setLamp(state) {
    lamp.setAttribute("data-state", state);
    var label = lamp.querySelector(".lamp-label");
    var sub = lamp.querySelector(".lamp-sub");
    if (label) label.textContent = LAMP[state].label;
    if (sub) sub.textContent = LAMP[state].sub;
  }

  // One span per line so the highlighted lines (the two attestation outcomes,
  // the forged-record line, the disagreeing metrics) can be styled without
  // touching the text.
  function classify(line) {
    if (/^\s+attestation\s+confirmed/.test(line)) return "t-confirmed";
    if (/^\s+attestation\s+divergent/.test(line)) return "t-divergent";
    if (/^\s+disagreed: /.test(line)) return "t-disagreed";
    if (/^\s+adversary: /.test(line)) return "t-adversary";
    if (/^\s+(ANDON DEMO|LEG \d|WHAT THIS SHOWED)/.test(line)) return "t-head";
    if (/^\s+THIS IS A STUB/.test(line)) return "t-stub";
    return "";
  }

  function lampFor(line) {
    if (/^\s+attestation\s+confirmed/.test(line)) return "confirmed";
    if (/^\s+attestation\s+divergent/.test(line)) return "divergent";
    if (/Trust so far: unwitnessed/.test(line)) return "self-report";
    return null;
  }

  function appendLine(text, cls) {
    var span = document.createElement("span");
    span.className = "t-line" + (cls ? " " + cls : "");
    span.textContent = text;
    screen.appendChild(span);
    screen.appendChild(document.createTextNode("\n"));
    return span;
  }

  var timer = null;
  var running = false;

  function stop() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    running = false;
  }

  // The final frame derives its lamp state from the transcript the same way
  // playback does: the last line that names an outcome wins. Hardcoding
  // "divergent" here would let the lamp claim an outcome a changed transcript
  // never reached.
  function renderAll() {
    stop();
    screen.textContent = "";
    var last = "idle";
    for (var i = 0; i < lines.length; i++) {
      appendLine(lines[i], classify(lines[i]));
      var state = lampFor(lines[i]);
      if (state) last = state;
    }
    setLamp(last);
    screen.scrollTop = screen.scrollHeight;
    if (status) status.textContent = "Playback complete. The full transcript is shown.";
    if (skip) skip.disabled = true;
  }

  // Pace: prose types at a few milliseconds a character; the block of
  // disagreeing metrics prints a line at a time, because reading each one
  // being typed adds nothing; blank lines are a beat.
  function play() {
    stop();
    screen.textContent = "";
    setLamp("idle");
    if (skip) skip.disabled = false;
    if (status) status.textContent = "Playing the recorded transcript.";
    running = true;
    var i = 0;

    function nextLine() {
      if (!running) return;
      if (i >= lines.length) {
        running = false;
        if (status) status.textContent = "Playback complete.";
        if (skip) skip.disabled = true;
        return;
      }
      var line = lines[i++];
      var cls = classify(line);
      var state = lampFor(line);
      if (line.trim() === "") {
        appendLine("", "");
        timer = setTimeout(nextLine, 140);
        return;
      }
      if (cls === "t-disagreed") {
        appendLine(line, cls);
        screen.scrollTop = screen.scrollHeight;
        timer = setTimeout(nextLine, 28);
        return;
      }
      var span = appendLine("", cls);
      var j = 0;
      var perChar = cls === "t-head" ? 14 : 5;
      function typeChar() {
        if (!running) return;
        if (j <= line.length) {
          span.textContent = line.slice(0, j);
          j += 1;
          screen.scrollTop = screen.scrollHeight;
          timer = setTimeout(typeChar, perChar);
        } else {
          if (state) setLamp(state);
          timer = setTimeout(nextLine, cls === "t-head" ? 420 : 60);
        }
      }
      typeChar();
    }
    nextLine();
  }

  if (replay) replay.addEventListener("click", play);
  if (skip) skip.addEventListener("click", renderAll);

  if (reducedMotion()) {
    renderAll();
  } else {
    play();
  }
})();
