// Библиотека и код схем встроены в HTML: сеть при открытии отчёта не нужна.
(function () {
  const diagrams = Array.from(document.querySelectorAll('pre.mermaid')).map(source => {
    const figure = document.createElement('figure');
    figure.className = 'report-diagram';
    figure.setAttribute('aria-label', 'Интерактивная схема');
    const controls = document.createElement('div');
    controls.className = 'diagram-controls';
    const viewport = document.createElement('div');
    viewport.className = 'diagram-viewport';
    viewport.textContent = 'Построение схемы…';
    figure.append(controls, viewport);
    source.replaceWith(figure);
    const item = {source: source.textContent, figure, controls, viewport, zoom: 1};
    function resize(mode) {
      if (!item.svg) return;
      const natural = item.svg.viewBox.baseVal.width || 800;
      item.zoom = mode === 'fit' ? Math.min(1, viewport.clientWidth / natural)
        : mode === 'actual' ? 1 : Math.max(0.05, Math.min(4, item.zoom * mode));
      item.svg.style.width = (natural * item.zoom) + 'px';
      item.svg.style.maxWidth = 'none';
      item.svg.style.height = 'auto';
    }
    [['−', 0.75, 'Уменьшить'], ['+', 1.5, 'Увеличить'],
     ['По ширине', 'fit', 'По ширине'], ['100%', 'actual', 'Исходный масштаб']]
      .forEach(([label, mode, title]) => {
        const button = document.createElement('button');
        button.type = 'button'; button.textContent = label;
        button.setAttribute('aria-label', title);
        button.addEventListener('click', () => resize(mode));
        controls.appendChild(button);
      });
    item.resize = resize;
    return item;
  });
  let queue = Promise.resolve();
  let revision = 0;
  window.renderReportDiagrams = function () {
    queue = queue.then(async function () {
      const current = ++revision;
      mermaid.initialize({startOnLoad: false, securityLevel: 'strict',
        theme: document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'default',
        fontFamily: 'Arial, sans-serif', flowchart: {htmlLabels: false}});
      for (let i = 0; i < diagrams.length; i++) {
        const item = diagrams[i];
        try {
          const result = await mermaid.render('report-diagram-' + current + '-' + i,
            item.source, item.viewport);
          item.viewport.innerHTML = result.svg;
          item.svg = item.viewport.querySelector('svg');
          if (result.bindFunctions) result.bindFunctions(item.viewport);
          item.controls.hidden = false;
          item.figure.dataset.state = 'rendered';
          item.resize('fit');
        } catch (error) {
          // Ошибка одной схемы не мешает остальным; исходник остаётся доступен.
          item.viewport.textContent = 'Не удалось построить эту схему.';
          const details = document.createElement('details');
          const summary = document.createElement('summary');
          summary.textContent = 'Показать исходник схемы';
          const pre = document.createElement('pre');
          pre.textContent = item.source;
          details.append(summary, pre); item.viewport.appendChild(details);
          item.controls.hidden = true;
          item.figure.dataset.state = 'error';
          console.warn('Ошибка схемы отчёта', error);
        }
      }
    });
    return queue;
  };
  window.renderReportDiagrams();
})();
