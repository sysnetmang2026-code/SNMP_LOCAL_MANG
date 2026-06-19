const navButtons = document.querySelectorAll("[data-view]");
const quickLinks = document.querySelectorAll("[data-view-link]");
const views = document.querySelectorAll(".view");

function showView(viewId) {
  views.forEach((view) => {
    view.classList.toggle("is-visible", view.id === viewId);
  });

  navButtons.forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === viewId);
  });
}

navButtons.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});

quickLinks.forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.viewLink));
});

document.getElementById("scanNow").addEventListener("click", () => {
  showView("scan");
});
