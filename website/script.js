document.querySelectorAll('[data-copy], [data-copy-target]').forEach((button) => {
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


document.querySelectorAll('[data-finding-tab]').forEach((tab) => {
  tab.addEventListener('click', () => {
    const target = tab.getAttribute('data-finding-tab');
    document.querySelectorAll('[data-finding-tab]').forEach((item) => {
      const active = item === tab;
      item.classList.toggle('is-active', active);
      item.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    document.querySelectorAll('[data-finding-pane]').forEach((pane) => {
      const active = pane.getAttribute('data-finding-pane') === target;
      pane.classList.toggle('is-active', active);
      pane.hidden = !active;
    });
  });
});


const lockLifecycle = document.querySelector('[data-lock-lifecycle]');

if (lockLifecycle) {
  const statusLabel = lockLifecycle.querySelector('[data-lock-status]');
  const timerLabel = lockLifecycle.querySelector('[data-lock-timer]');
  const progressBar = lockLifecycle.querySelector('[data-lock-progress]');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const phases = [
    { state: 'idle', label: 'READY', duration: 1800 },
    { state: 'red', label: 'RISK', duration: 1400 },
    { state: 'amber', label: 'SCANNING', duration: 2800 },
    { state: 'green', label: 'CLEAR', duration: 2200 },
  ];

  if (reducedMotion) {
    lockLifecycle.dataset.state = 'green';
    statusLabel.textContent = 'CLEAR';
    timerLabel.textContent = 'READY';
  } else {
    let phaseIndex = 0;
    let phaseStartedAt = performance.now();
    let animationFrame = 0;

    const setPhase = (index, now) => {
      const phase = phases[index];
      lockLifecycle.dataset.state = phase.state;
      statusLabel.textContent = phase.label;
      phaseStartedAt = now;
      if (progressBar) progressBar.style.transform = 'scaleX(0)';
    };

    const tickLifecycle = (now) => {
      const phase = phases[phaseIndex];
      const elapsed = now - phaseStartedAt;

      if (elapsed >= phase.duration) {
        phaseIndex = (phaseIndex + 1) % phases.length;
        setPhase(phaseIndex, now);
      }

      const activePhase = phases[phaseIndex];
      const activeElapsed = Math.max(0, now - phaseStartedAt);
      const remaining = Math.max(0, activePhase.duration - activeElapsed);
      timerLabel.textContent = `${(remaining / 1000).toFixed(1)}s`;

      if (progressBar) {
        const progress = Math.min(1, activeElapsed / activePhase.duration);
        progressBar.style.transform = `scaleX(${progress})`;
      }

      animationFrame = window.requestAnimationFrame(tickLifecycle);
    };

    setPhase(0, phaseStartedAt);
    animationFrame = window.requestAnimationFrame(tickLifecycle);

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        phaseStartedAt = performance.now();
      }
    }, { passive: true });

    window.addEventListener('pagehide', () => {
      window.cancelAnimationFrame(animationFrame);
    }, { once: true });
  }
}
