document.addEventListener("submit", (event) => {
    const form = event.target;
    const message = form.dataset.confirm;

    if (message && !window.confirm(message)) {
        event.preventDefault();
    }
});

document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy-target]");
    if (!button) return;

    const target = document.getElementById(button.dataset.copyTarget);
    if (!target) return;

    try {
        await navigator.clipboard.writeText(target.innerText);
        const original = button.innerText;
        button.innerText = "Copiado";
        setTimeout(() => button.innerText = original, 1600);
    } catch (_) {
        window.alert("Não foi possível copiar automaticamente.");
    }
});
