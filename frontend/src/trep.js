import html from './trep.html';
import css from './trep.css';

document.addEventListener('DOMContentLoaded', async () => {
    document.body.replaceChildren(...new DOMParser().parseFromString(html, 'text/html').body.children);
    document.adoptedStyleSheets = [await (new CSSStyleSheet()).replace(css)];
});