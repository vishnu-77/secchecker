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
