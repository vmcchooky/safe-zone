(function() {
  const blockForm = document.getElementById('block-report-form');
  const blockStatus = document.getElementById('block-report-status');
  const blockToast = document.getElementById('block-report-toast');

  if (!blockForm || !blockStatus || !blockToast || !window.fetch) {
    return;
  }

  let blockToastTimer;

  function showBlockToast(message) {
    const toastText = blockToast.querySelector('span');
    if (toastText && message) {
      toastText.textContent = message;
    }
    blockToast.classList.remove('show');
    void blockToast.offsetWidth;
    blockToast.classList.add('show');
    window.clearTimeout(blockToastTimer);
    blockToastTimer = window.setTimeout(() => {
      blockToast.classList.remove('show');
    }, 3400);
  }

  blockForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = blockForm.querySelector('button[type="submit"]');
    const originalLabel = submit ? submit.textContent : '';

    if (submit) {
      submit.disabled = true;
      submit.textContent = 'Đang gửi...';
    }

    try {
      const response = await fetch(blockForm.action, {
        method: blockForm.method,
        body: new FormData(blockForm),
      });
      if (!response.ok) {
        throw new Error('Request failed');
      }
      blockStatus.classList.add('show');
      showBlockToast('Đã gửi yêu cầu của bạn.');
      blockForm.reset();
    } catch {
      blockForm.submit();
    } finally {
      if (submit) {
        submit.disabled = false;
        submit.textContent = originalLabel;
      }
    }
  });
})();
