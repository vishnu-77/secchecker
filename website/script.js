document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    const value = button.getAttribute('data-copy') || '';
    try {
      await navigator.clipboard.writeText(value);
      const previous = button.textContent;
      button.textContent = 'COPIED';
      window.setTimeout(() => { button.textContent = previous; }, 1400);
    } catch {
      button.textContent = 'SELECT';
      const code = button.parentElement?.querySelector('code');
      if (code) {
        const range = document.createRange();
        range.selectNodeContents(code);
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
  let runToken = 0;
  let hasAutoRun = false;

  const sleep = (ms, token) => new Promise((resolve) => {
    window.setTimeout(() => resolve(token === runToken), ms);
  });

  consoleBar.innerHTML = `
    <span>secchecker / local</span>
    <div class="console-controls">
      <span class="demo-state" aria-live="polite">
        <i class="demo-dot"></i><b>READY</b>
      </span>
      <button class="demo-replay" type="button">RUN DEMO</button>
    </div>`;

  const replayButton = consoleBar.querySelector('.demo-replay');
  const state = consoleBar.querySelector('.demo-state');
  const stateText = state.querySelector('b');

  demoConsole.classList.add('demo-enhanced');

  const setState = (name) => {
    state.classList.remove('is-ready', 'is-running', 'is-complete');
    state.classList.add(`is-${name}`);
    stateText.textContent = name === 'running' ? 'SCANNING' : name === 'complete' ? 'COMPLETE' : 'READY';
  };

  const resetDemo = () => {
    terminal.innerHTML = '<span class="demo-command-line"><span class="console-prompt">$</span> <span class="demo-command"></span><span class="console-caret">▌</span></span><span class="demo-output"></span>';
    report.classList.remove('is-visible');
    replayButton.textContent = 'RUNNING…';
    replayButton.disabled = true;
    setState('running');
  };

  const appendLine = (output, html) => {
    const line = document.createElement('span');
    line.className = 'demo-line';
    line.innerHTML = html;
    output.appendChild(line);
    window.requestAnimationFrame(() => line.classList.add('is-visible'));
  };

  const runDemo = async () => {
    runToken += 1;
    const token = runToken;
    resetDemo();

    const command = 'secchecker . --type llm --format sarif --verbose';
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

    const lines = [
      ['<span class="console-info">[*]</span> Scanning: .', 420],
      ['<span class="console-info">[*]</span> Scan type: llm', 360],
      ['<span class="console-info">[*]</span> Format: sarif', 390],
      ['<span class="console-info">[*]</span> 3 finding(s) across 2 file(s)', 520],
      ['<span class="console-ok">[+]</span> Report: secchecker_report.sarif', 460],
    ];

    for (const [html, delay] of lines) {
      appendLine(output, html);
      if (!(await sleep(delay, token))) return;
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
