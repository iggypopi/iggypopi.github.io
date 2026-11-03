---
title: Tools
icon: fas fa-screwdriver-wrench
order: 3
description: >-
  Security tooling built by iggyp0pi, including ActChain, a supply chain
  scanner for GitHub Actions workflows and their dependencies.
---

Things I build when the tooling that already exists does not do the job.
{% for tool in site.data.tools %}
## {{ tool.name }}{% if tool.status %} <span class="status-pill">{{ tool.status }}</span>{% endif %}

{{ tool.summary }}
{% if tool.repo %}
[Source on GitHub]({{ tool.repo }})
{% endif %}
{%- assign related = site.tags[tool.tag] -%}
{% if related and related.size > 0 %}
Posts about {{ tool.name }}:
{% for p in related %}
- [{{ p.title }}]({{ p.url | relative_url }})
{%- endfor %}
{% endif %}
{% endfor %}
