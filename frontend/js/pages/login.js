import * as api from '../api.js';
import { state } from '../state.js';

export function renderLogin(root, onSuccess) {
  root.innerHTML = `
    <main class="login">
      <div class="login-box">
        <div class="login-scanline"></div>
        <div class="brand"><strong>NIDPS</strong></div>
        <p class="muted">authentication required</p>
        <form id="login-form">
          <label for="username">USERNAME
            <input id="username" name="username" autocomplete="username" autofocus />
          </label>
          <label for="password">PASSWORD
            <input id="password" name="password" type="password" autocomplete="current-password" />
          </label>
          <p class="login-error" role="alert" id="login-error" hidden></p>
          <button class="term-button" type="submit">[ LOGIN ]</button>
        </form>
        <small class="muted">Access attempts are recorded in the audit log.</small>
      </div>
    </main>`;

  const form = root.querySelector('#login-form');
  const errorEl = root.querySelector('#login-error');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = form.username.value.trim();
    const password = form.password.value;
    if (!username || !password) {
      errorEl.textContent = 'err: username and password are required';
      errorEl.hidden = false;
      return;
    }
    errorEl.hidden = true;
    try {
      const { token } = await api.login(username, password);
      state.set('sessionToken', token);
      onSuccess();
    } catch (err) {
      errorEl.textContent = `err: ${err.message || 'login failed'}`;
      errorEl.hidden = false;
    }
  });
}
