// Chart host: plain SVG drawn at the container's real width (so text never stretches), redrawn on resize.

const observers = new WeakMap();

// Bind a draw(width) => svgString function to a container and keep it sized.
export function bindChart(el, draw, { height } = {}) {
  if (!el) return;
  const paint = () => {
    const w = Math.max(240, Math.floor(el.clientWidth));
    el.innerHTML = draw(w, height);
  };
  paint();
  observers.get(el)?.disconnect();
  let last = el.clientWidth;
  const ro = new ResizeObserver(() => {
    if (Math.abs(el.clientWidth - last) < 2) return;
    last = el.clientWidth;
    paint();
  });
  ro.observe(el);
  observers.set(el, ro);
}
