(function () {
  "use strict";

  function slugify(value) {
    return value
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  function uniqueId(base, used) {
    var id = base;
    var suffix = 2;

    while (used.has(id) || document.getElementById(id)) {
      id = base + "-" + suffix;
      suffix += 1;
    }

    used.add(id);
    return id;
  }

  function buildList(nodes) {
    var list = document.createElement("ol");

    nodes.forEach(function (node) {
      var item = document.createElement("li");
      var link = document.createElement("a");

      link.href = "#" + node.id;
      link.textContent = node.text;
      item.appendChild(link);

      if (node.children.length) {
        item.appendChild(buildList(node.children));
      }

      list.appendChild(item);
    });

    return list;
  }

  function init() {
    var toc = document.querySelector("[data-toc]");
    var content = document.querySelector("main#content");

    if (!toc || !content) {
      return;
    }

    var headings = Array.prototype.slice
      .call(content.querySelectorAll("h1, h2, h3, h4, h5, h6"))
      .filter(function (heading) {
        return !heading.closest("[data-toc]") && heading.textContent.trim();
      });

    if (headings.length < 2) {
      return;
    }

    var used = new Set();
    var minLevel = headings.reduce(function (min, heading) {
      return Math.min(min, Number(heading.tagName.charAt(1)));
    }, 6);

    var root = { level: minLevel - 1, children: [] };
    var stack = [root];

    headings.forEach(function (heading, index) {
      var level = Number(heading.tagName.charAt(1));
      var text = heading.textContent.trim().replace(/\s+/g, " ");

      if (heading.id) {
        used.add(heading.id);
      } else {
        var base = slugify(text) || "section-" + (index + 1);
        heading.id = uniqueId(base, used);
      }

      while (stack.length > 1 && stack[stack.length - 1].level >= level) {
        stack.pop();
      }

      var node = {
        level: level,
        id: heading.id,
        text: text,
        children: []
      };

      stack[stack.length - 1].children.push(node);
      stack.push(node);
    });

    var nav = toc.querySelector(".toc-nav");
    if (!nav) {
      return;
    }

    nav.textContent = "";
    nav.appendChild(buildList(root.children));
    toc.hidden = false;

    var desktop = typeof window !== "undefined" && window.matchMedia
      ? window.matchMedia("(min-width: 861px)").matches
      : false;
    toc.open = desktop;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
