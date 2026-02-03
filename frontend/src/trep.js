import html from './trep.html';
import css from './trep.css';
import user from './user.xml';

document.addEventListener('DOMContentLoaded', async () => {
    let confInput, conf = null, enableButton, usersInput, users = null, generateButton;
    document.body.replaceChildren(...new DOMParser().parseFromString(html, 'text/html').body.children);
    document.adoptedStyleSheets = [await (new CSSStyleSheet()).replace(css)];
    confInput = document.querySelector('#conf');
    usersInput = document.querySelector('#users');
    generateButton = document.querySelector('#generate');

    generateButton.addEventListener('click', (event) => {
        console.log(event.target, conf, users);
    });

    enableButton = () => {
        generateButton.disabled = !conf || !users;
    }

    confInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                conf = new DOMParser().parseFromString(e.target.result, 'text/xml').documentElement;
                conf.querySelectorAll('user').forEach(u => {
                    if (u.querySelector("name").textContent.match(/^ctx\d+$/)) u.remove();
                });
                enableButton();
            };
            reader.readAsText(file, 'utf-8');
        }
    });

    usersInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = (e) => {
                let user, password;
                users = e.target.result.split('\n').map(line => ({ 0: user, 1: password } = line.split(','))).slice(1);
                enableButton();
            };
            reader.readAsText(file);
        }
    });
});