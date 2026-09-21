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
  const cliState = lockLifecycle.querySelector('[data-cli-state]');
  const cliResult = lockLifecycle.querySelector('[data-cli-result]');
  const cliSteps = [...lockLifecycle.querySelectorAll('[data-cli-step]')];
  const foldSteps = [...lockLifecycle.querySelectorAll('[data-lock-fold]')];
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const phases = [
    { state: 'idle', label: 'READY', duration: 1800 },
    { state: 'red', label: 'RISK', duration: 1800 },
    { state: 'dock', label: 'CONNECT', duration: 900 },
    { state: 'amber', label: 'SCANNING', duration: 5200 },
    { state: 'resolve', label: 'VERIFY', duration: 1200 },
    { state: 'green', label: 'DONE', duration: 2300 },
    { state: 'exit', label: 'RESET', duration: 900 },
    { state: 'rest', label: 'READY', duration: 1500 },
  ];

  const resetInspection = () => {
    cliSteps.forEach((row) => {
      row.classList.remove('is-active', 'is-done');
      const mark = row.querySelector('b');
      if (mark) mark.textContent = '·';
    });
    foldSteps.forEach((fold) => fold.classList.remove('is-active', 'is-done'));
  };

  const updateInspection = (progress) => {
    const count = cliSteps.length;
    const exact = Math.min(count - 0.001, Math.max(0, progress) * count);
    const activeIndex = Math.floor(exact);

    cliSteps.forEach((row, index) => {
      row.classList.toggle('is-done', index < activeIndex);
      row.classList.toggle('is-active', index === activeIndex);
      const mark = row.querySelector('b');
      if (mark) mark.textContent = index < activeIndex ? '✓' : index === activeIndex ? '■' : '·';
    });

    foldSteps.forEach((fold, index) => {
      fold.classList.toggle('is-done', index < activeIndex);
      fold.classList.toggle('is-active', index === activeIndex);
    });
  };

  const completeInspection = () => {
    cliSteps.forEach((row) => {
      row.classList.remove('is-active');
      row.classList.add('is-done');
      const mark = row.querySelector('b');
      if (mark) mark.textContent = '✓';
    });
    foldSteps.forEach((fold) => {
      fold.classList.remove('is-active');
      fold.classList.add('is-done');
    });
  };

  if (reducedMotion) {
    lockLifecycle.dataset.state = 'green';
    statusLabel.textContent = 'DONE';
    timerLabel.textContent = 'READY';
    cliState.textContent = 'DONE';
    cliResult.textContent = 'SCAN COMPLETE';
    completeInspection();
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

      if (phase.state === 'idle' || phase.state === 'red' || phase.state === 'rest') {
        resetInspection();
        cliState.textContent = 'STANDBY';
        cliResult.textContent = 'WAITING';
      } else if (phase.state === 'dock') {
        resetInspection();
        cliState.textContent = 'LINK';
        cliResult.textContent = 'CONNECTING';
      } else if (phase.state === 'amber') {
        cliState.textContent = 'RUN';
        cliResult.textContent = 'INSPECTING';
      } else if (phase.state === 'resolve') {
        completeInspection();
        cliState.textContent = 'VERIFY';
        cliResult.textContent = 'EVIDENCE READY';
      } else if (phase.state === 'green') {
        completeInspection();
        cliState.textContent = 'DONE';
        cliResult.textContent = 'SCAN COMPLETE';
      } else if (phase.state === 'exit') {
        cliState.textContent = 'DONE';
        cliResult.textContent = 'SCAN COMPLETE';
      }
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
      const progress = Math.min(1, activeElapsed / activePhase.duration);
      const remaining = Math.max(0, activePhase.duration - activeElapsed);
      timerLabel.textContent = `${(remaining / 1000).toFixed(1)}s`;

      if (progressBar) progressBar.style.transform = `scaleX(${progress})`;
      if (activePhase.state === 'amber') updateInspection(progress);

      animationFrame = window.requestAnimationFrame(tickLifecycle);
    };

    setPhase(0, phaseStartedAt);
    animationFrame = window.requestAnimationFrame(tickLifecycle);

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        phaseStartedAt = performance.now();
        setPhase(phaseIndex, phaseStartedAt);
      }
    }, { passive: true });

    window.addEventListener('pagehide', () => {
      window.cancelAnimationFrame(animationFrame);
    }, { once: true });
  }
}
