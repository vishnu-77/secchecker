document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const targetSelector = button.getAttribute('data-copy-target');
    const target = targetSelector ? document.querySelector(targetSelector) : null;
    const value = target ? target.textContent.trim() : (button.getAttribute('data-copy') || '');
    try {
      await navigator.clipboard.writeText(value);
      const previous = button.textContent;
      button.textContent = 'COPIED';
      window.setTimeout(() => { button.textContent = previous; }, 1400);
    } catch {
      button.textContent = 'SELECT';
      const copySource = target || button.parentElement?.querySelector('code, pre');
      if (copySource) {
        const range = document.createRange();
        range.selectNodeContents(copySource);
        const selection = window.getSelection();
        selection?.removeAllRanges();
        selection?.addRange(range);
      }
    }
  });
});

const demoConsole = document.querySelector('.console');
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

if (demoConsole && !prefersReducedMotion) {
  const consoleBar = demoConsole.querySelector('.console-bar');
  const terminal = demoConsole.querySelector('pre');
  const report = demoConsole.querySelector('.console-report');
  // Replay the visible captured transcript, so the animation cannot drift
  // from the accessible, reduced-motion and no-JavaScript version.
  const command = terminal.querySelector('.demo-command-source').textContent.replace(/^\$ /, '');
  const capturedLines = [...terminal.querySelectorAll('[data-scan-line]')].map((line) => line.cloneNode(true));
  let runToken = 0;
  let hasAutoRun = false;

  const sleep = (ms, token) => new Promise((resolve) => {
    window.setTimeout(() => resolve(token === runToken), ms);
  });

  consoleBar.innerHTML = `
    <span>secchecker / recorded scan</span>
    <div class="console-controls">
      <span class="demo-state" aria-live="polite">
        <i class="demo-dot"></i><b>RECORDED</b>
      </span>
      <button class="demo-replay" type="button">REPLAY SCAN</button>
    </div>`;

  const replayButton = consoleBar.querySelector('.demo-replay');
  const state = consoleBar.querySelector('.demo-state');
  const stateText = state.querySelector('b');

  demoConsole.classList.add('demo-enhanced');

  const setState = (name) => {
    state.classList.remove('is-ready', 'is-running', 'is-complete');
    state.classList.add(`is-${name}`);
    stateText.textContent = name === 'running' ? 'REPLAYING' : name === 'complete' ? 'COMPLETE' : 'RECORDED';
  };

  const resetDemo = () => {
    terminal.innerHTML = '<span class="demo-command-line"><span class="console-prompt">$</span> <span class="demo-command"></span><span class="console-caret">▌</span></span><span class="demo-output"></span>';
    report.classList.remove('is-visible');
    replayButton.textContent = 'REPLAYING…';
    replayButton.disabled = true;
    setState('running');
  };

  const appendLine = (output, capturedLine) => {
    const line = capturedLine.cloneNode(true);
    line.className = 'demo-line';
    output.appendChild(line);
    window.requestAnimationFrame(() => line.classList.add('is-visible'));
  };

  const runDemo = async () => {
    runToken += 1;
    const token = runToken;
    resetDemo();

    const commandNode = terminal.querySelector('.demo-command');
    const caret = terminal.querySelector('.console-caret');
    const output = terminal.querySelector('.demo-output');

    for (const char of command) {
      if (token !== runToken) return;
      commandNode.textContent += char;
      const keepGoing = await sleep(18, token);
      if (!keepGoing) return;
    }

    caret.remove();
    if (!(await sleep(320, token))) return;

    for (const line of capturedLines) {
      appendLine(output, line);
      if (!(await sleep(420, token))) return;
    }

    report.classList.add('is-visible');
    setState('complete');
    replayButton.textContent = 'REPLAY';
    replayButton.disabled = false;
  };

  replayButton.addEventListener('click', runDemo);

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting && !hasAutoRun) {
        hasAutoRun = true;
        runDemo();
        observer.disconnect();
      }
    });
  }, { threshold: 0.35 });

  observer.observe(demoConsole);
}
