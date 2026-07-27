/* BlastRadius landing page.
 *
 * One job: reveal the fault sequence as the reader arrives at it, so the nine seconds
 * are read at the pace of the events rather than absorbed as a block of text.
 *
 * Deliberately tiny and dependency-free. A tool whose pitch is "zero dependencies, audit
 * it yourself" should not ship a landing page carrying a framework.
 *
 * The `js` class is set here rather than in the HTML so that the rows are visible by
 * default — if this script fails to load or throws, the sequence still reads. Hiding
 * content in CSS and revealing it with JS is how pages end up blank for the people whose
 * network dropped a file.
 */
(function () {
  'use strict';

  var rows = document.querySelectorAll('.ledger__row');
  if (!rows.length) return;

  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced || !('IntersectionObserver' in window)) return;

  document.documentElement.classList.add('js');

  // Thresholds are deliberately near-zero. An earlier version used threshold 0.25 with a
  // negative bottom margin, which looked better in slow scrolling and left rows stranded at
  // opacity 0 when someone flicked past them — the row never became "25% visible" so the
  // callback never ran. Any content that JS hides must be trivially easy for JS to show.
  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry, i) {
      if (!entry.isIntersecting) return;
      var el = entry.target;
      window.setTimeout(function () {
        el.classList.add('is-in');
      }, i * 90);
      observer.unobserve(el);
    });
  }, { rootMargin: '0px 0px 0px 0px', threshold: 0.01 });

  rows.forEach(function (row) { observer.observe(row); });

  // Failsafe. If the observer misbehaves in some browser, the sequence must not stay blank —
  // reveal everything shortly after load regardless. A missed animation is a small loss; a
  // page that silently withholds its central content is not.
  window.setTimeout(function () {
    rows.forEach(function (row) { row.classList.add('is-in'); });
  }, 1500);
}());
