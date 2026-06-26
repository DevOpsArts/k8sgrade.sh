(() => {
  const copyButton = document.querySelector('[data-copy]');
  if (!copyButton) {
    return;
  }

  copyButton.addEventListener('click', async () => {
    const text = copyButton.getAttribute('data-copy') || '';
    try {
      await navigator.clipboard.writeText(text);
      const previous = copyButton.textContent;
      copyButton.textContent = 'Copied';
      setTimeout(() => {
        copyButton.textContent = previous;
      }, 1200);
    } catch (_error) {
      copyButton.textContent = 'Copy failed';
      setTimeout(() => {
        copyButton.textContent = 'Copy Start Command';
      }, 1200);
    }
  });
})();
