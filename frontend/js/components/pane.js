// A titled panel, matching the v0 mockup's [ TITLE ] bracketed header convention.
export function pane(title, innerHtml, { className = '' } = {}) {
  return `
    <section class="pane ${className}">
      <header><span>[ ${title} ]</span><b>+</b></header>
      ${innerHtml}
    </section>`;
}
