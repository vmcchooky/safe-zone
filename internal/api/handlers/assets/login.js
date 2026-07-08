(function() {
  const form = document.getElementById('adminLoginForm');
  const btn = document.getElementById('submitBtn');
  const btnText = document.getElementById('btnText');
  const btnIcon = document.getElementById('btnIcon');
  const inlineError = document.getElementById('inlineError');
  const toast = document.getElementById('toast');

  if (!form || !btn || !btnText || !btnIcon || !inlineError || !toast) {
    return;
  }

  let toastTimer;
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const motionOK = () => !motionQuery.matches;

  document.addEventListener('contextmenu', event => {
    if (document.body.classList.contains('sentinel-access-page')) {
      event.preventDefault();
    }
  });

  function pulseNode(el, className) {
    if (!el || !motionOK()) return;
    el.classList.remove(className);
    void el.offsetWidth;
    el.classList.add(className);
  }

  function showToast(message) {
    inlineError.textContent = message;
    inlineError.classList.add('show');
    if (motionOK()) {
      inlineError.classList.add('comet-in');
    }

    toast.textContent = message;
    toast.className = 'toast err show';
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => {
      toast.classList.remove('show');
      if (motionOK()) {
        toast.classList.add('is-closing');
        window.setTimeout(() => toast.classList.remove('is-closing'), 190);
      }
    }, 3000);
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    btn.disabled = true;
    inlineError.classList.remove('show', 'comet-in');

    btnText.textContent = 'Verifying...';
    pulseNode(btnText, 'star-glint');
    btnIcon.textContent = '';

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    try {
      const response = await fetch('/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.error || 'Authentication failed');
      }

      btnText.textContent = 'Access granted';
      btnIcon.textContent = 'OK';
      pulseNode(btnText, 'star-glint');
      window.setTimeout(() => window.location.reload(), 500);
    } catch (err) {
      showToast(err && err.message ? err.message : 'Authentication failed');
      btn.disabled = false;
      btnText.textContent = 'Establish connection';
      btnIcon.textContent = '->';
    }
  });
})();
