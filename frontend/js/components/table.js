// table(headers, rows): rows is an array of arrays of pre-escaped HTML strings. Callers build
// cell content (status pills, buttons) themselves and pass finished markup here.
export function table(headers, rows, { rowAttrs = () => '' } = {}) {
  const head = `<tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr>`;
  const body = rows
    .map((row, i) => `<tr ${rowAttrs(row, i)}>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`)
    .join('');
  return `<div class="table-wrap"><table><thead>${head}</thead><tbody>${body}</tbody></table></div>`;
}
